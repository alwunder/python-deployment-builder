"""Acquire and verify the exact uv artifact selected by a deployment plan."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from urllib.request import Request, urlopen

from python_deployment_builder.models import BootstrapArtifact

DownloadOpener = Callable[..., object]


class PreparationError(RuntimeError):
    """Developer preparation could not be completed safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_uv_cache_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return base / "PythonDeploymentBuilder" / "developer-cache" / "uv"


def _safe_archive_member(member: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(member.filename.replace("\\", "/"))
    file_type = (member.external_attr >> 16) & 0o170000
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and not member.flag_bits & 0x1
        and file_type != stat.S_IFLNK
        and member.file_size <= 256 * 1024 * 1024
    )


def extract_verified_uv(archive: Path, destination: Path, member_name: str = "uv.exe") -> Path:
    """Extract one uv executable after validating every ZIP member."""

    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if not members or any(not _safe_archive_member(item) for item in members):
            raise PreparationError("The pinned uv ZIP contains an unsafe archive member.")
        candidates = [item for item in members if PurePosixPath(item.filename).name == member_name]
        if len(candidates) != 1:
            raise PreparationError(
                f"The pinned uv ZIP must contain exactly one {member_name}; "
                f"found {len(candidates)}."
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".extracting")
        with bundle.open(candidates[0]) as source, temporary.open("wb") as target:
            shutil.copyfileobj(source, target)
        temporary.replace(destination)
    return destination


def verify_uv_version(
    executable: Path,
    expected_version: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    try:
        result = runner(
            [str(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreparationError(f"The verified uv executable could not run: {exc}") from exc
    actual = (result.stdout or result.stderr).strip()
    version_fields = actual.split()
    if (
        result.returncode != 0
        or len(version_fields) < 2
        or version_fields[:2] != ["uv", expected_version]
    ):
        raise PreparationError(
            f"Pinned uv version verification failed: expected uv {expected_version}, "
            f"received {actual or f'exit code {result.returncode}'}."
        )


def _download(url: str, destination: Path, opener: DownloadOpener) -> None:
    request = Request(url, headers={"User-Agent": "python-deployment-builder/0.1"})
    try:
        with opener(request, timeout=60) as response, destination.open("wb") as target:
            shutil.copyfileobj(response, target)
    except (OSError, ValueError) as exc:
        raise PreparationError(
            f"Could not download the pinned uv artifact over HTTPS: {exc}"
        ) from exc


def acquire_pinned_uv(
    artifact: BootstrapArtifact,
    *,
    cache_root: Path | None = None,
    opener: DownloadOpener = urlopen,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    """Return a developer-cached uv.exe rooted in a verified official archive."""

    if not artifact.url.lower().startswith("https://"):
        raise PreparationError("Pinned uv acquisition requires an HTTPS artifact URL.")
    root = (cache_root or default_uv_cache_root()) / artifact.version / artifact.architecture
    archive = root / Path(artifact.url).name
    executable = root / artifact.archive_member
    root.mkdir(parents=True, exist_ok=True)

    if not archive.is_file() or sha256_file(archive) != artifact.sha256.lower():
        with NamedTemporaryFile(prefix="uv-", suffix=".download", dir=root, delete=False) as temp:
            temporary = Path(temp.name)
        try:
            _download(artifact.url, temporary, opener)
            actual = sha256_file(temporary)
            if actual != artifact.sha256.lower():
                raise PreparationError(
                    "Pinned uv archive SHA-256 mismatch: "
                    f"expected {artifact.sha256.lower()}, received {actual}."
                )
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)

    if sha256_file(archive) != artifact.sha256.lower():
        raise PreparationError("Cached uv archive failed its pinned SHA-256 verification.")
    extract_verified_uv(archive, executable, artifact.archive_member)
    verify_uv_version(executable, artifact.version, runner=runner)
    return executable
