"""Repository materialization without requiring Git or executing target code."""

from __future__ import annotations

import hashlib
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_EXTRACTED_BYTES = 750 * 1024 * 1024
MAX_MEMBER_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 50_000


class RepositoryLoadError(ValueError):
    """Raised when a repository cannot be safely materialized."""


@dataclass(frozen=True)
class MaterializedRepository:
    root: Path
    source: str
    source_kind: str


def parse_public_github_url(value: str) -> tuple[str, str] | None:
    """Return owner/repository for a public GitHub repository URL."""

    parsed = urlparse(value)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() not in {
        "github.com",
        "www.github.com",
    }:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        return None
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not owner or not repository or not set(owner + repository) <= allowed:
        return None
    return owner, repository


def _safe_member_path(destination: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    if "\x00" in normalized or normalized.startswith("/"):
        raise RepositoryLoadError(f"Unsafe archive member path: {member_name!r}")
    pure_path = PurePosixPath(normalized)
    if not pure_path.parts or ".." in pure_path.parts or ":" in pure_path.parts[0]:
        raise RepositoryLoadError(f"Unsafe archive member path: {member_name!r}")
    target = destination.joinpath(*pure_path.parts)
    try:
        target.resolve(strict=False).relative_to(destination.resolve())
    except ValueError as exc:
        raise RepositoryLoadError(f"Archive path escapes destination: {member_name!r}") from exc
    return target


def safe_extract_zip(archive: Path, destination: Path) -> Path:
    """Extract a ZIP after traversal, link, encryption, and size checks."""

    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise RepositoryLoadError("Repository archive contains too many entries.")
        total_size = sum(member.file_size for member in members)
        if total_size > MAX_EXTRACTED_BYTES:
            raise RepositoryLoadError("Repository archive is too large after extraction.")
        for member in members:
            if member.flag_bits & 0x1:
                raise RepositoryLoadError("Encrypted repository archives are not supported.")
            if member.file_size > MAX_MEMBER_BYTES:
                raise RepositoryLoadError(f"Archive member is too large: {member.filename}")
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise RepositoryLoadError(
                    f"Archive symbolic links are not allowed: {member.filename}"
                )
            target = _safe_member_path(destination, member.filename)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)

    children = [child for child in destination.iterdir() if child.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return destination


def materialize_git_head_snapshot(archive: Path, destination: Path) -> set[str]:
    """Materialize regular files from a locally generated Git HEAD archive.

    This is deliberately separate from ``safe_extract_zip``: external archives must
    reject links, while this read-only Git provenance snapshot can skip link entries
    so unrelated links cannot poison analysis of regular HEAD files.
    """

    destination.mkdir(parents=True, exist_ok=True)
    skipped_symlinks: set[str] = set()
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise RepositoryLoadError("Git HEAD archive contains too many entries.")
        if sum(member.file_size for member in members) > MAX_EXTRACTED_BYTES:
            raise RepositoryLoadError("Git HEAD archive is too large after extraction.")
        for member in members:
            if member.flag_bits & 0x1:
                raise RepositoryLoadError("Encrypted Git HEAD archives are not supported.")
            if member.file_size > MAX_MEMBER_BYTES:
                raise RepositoryLoadError(f"Git HEAD member is too large: {member.filename}")
            target = _safe_member_path(destination, member.filename)
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                skipped_symlinks.add(PurePosixPath(member.filename).as_posix())
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise RepositoryLoadError(
                    f"Unsupported Git HEAD archive member type: {member.filename}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    return skipped_symlinks


def _download_github_archive(owner: str, repository: str, destination: Path) -> None:
    url = f"https://api.github.com/repos/{owner}/{repository}/zipball"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "pdbuilder/0.1"},
    )
    received = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            destination.open("wb") as output,
        ):
            while chunk := response.read(1024 * 1024):
                received += len(chunk)
                if received > MAX_ARCHIVE_BYTES:
                    raise RepositoryLoadError("Repository download exceeds the size limit.")
                output.write(chunk)
    except RepositoryLoadError:
        raise
    except Exception as exc:
        raise RepositoryLoadError(f"Could not download public GitHub repository: {exc}") from exc


@contextmanager
def materialize_repository(value: str | Path) -> Iterator[MaterializedRepository]:
    """Yield a local repository root and clean temporary URL downloads afterward."""

    candidate = Path(value).expanduser()
    if candidate.exists():
        root = candidate.resolve()
        if not root.is_dir():
            raise RepositoryLoadError(f"Repository path is not a directory: {root}")
        yield MaterializedRepository(root=root, source=str(root), source_kind="local")
        return

    github = parse_public_github_url(str(value))
    if github is None:
        raise RepositoryLoadError(
            "Repository must be an existing local directory or a public github.com "
            "owner/repository URL."
        )
    owner, repository = github
    with tempfile.TemporaryDirectory(prefix="pdbuilder-repository-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "repository.zip"
        extracted = temporary_root / "extracted"
        _download_github_archive(owner, repository, archive)
        root = safe_extract_zip(archive, extracted)
        yield MaterializedRepository(root=root, source=str(value), source_kind="github_archive")


def repository_fingerprint(root: Path, files: list[Path] | None = None) -> str:
    """Fingerprint caller-selected deployment inputs without reading VCS state."""

    digest = hashlib.sha256()
    names = {
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        ".python-version",
    }
    candidates = (
        list(files)
        if files is not None
        else [path for path in root.rglob("*.py") if ".git" not in path.parts]
    )
    candidates.extend(path for path in root.iterdir() if path.is_file() and path.name in names)
    for path in sorted(set(candidates), key=lambda item: item.relative_to(root).as_posix().lower()):
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest.update(relative.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()
