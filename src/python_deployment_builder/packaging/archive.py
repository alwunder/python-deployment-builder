"""Deterministic ZIP creation and traversal-safe verification extraction."""

from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_FILE_MODE = stat.S_IFREG | 0o644


class ArchiveSafetyError(ValueError):
    """An archive or staged-kit path is unsafe for release packaging."""


def collect_kit_files(kit_root: Path) -> list[tuple[str, Path]]:
    """Return sorted POSIX archive names and source files, rejecting links."""

    root = kit_root.resolve()
    if not root.is_dir():
        raise ArchiveSafetyError(f"Deployment kit directory does not exist: {root}")
    files: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ArchiveSafetyError(
                f"Deployment kits containing symbolic links cannot be packaged: "
                f"{path.relative_to(root)}"
            )
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files.append((relative, path))
    if not files:
        raise ArchiveSafetyError("Deployment kit contains no files.")
    return sorted(files, key=lambda item: item[0])


def write_deterministic_zip(kit_root: Path, destination: Path) -> list[str]:
    """Write kit contents with stable ordering, metadata, and no wrapper directory."""

    files = collect_kit_files(kit_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for relative, path in files:
            info = zipfile.ZipInfo(relative, date_time=FIXED_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = FIXED_FILE_MODE << 16
            info.internal_attr = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(
                info,
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    return [item[0] for item in files]


def _validated_member_path(destination: Path, member: zipfile.ZipInfo) -> Path:
    name = member.filename
    if not name or "\\" in name:
        raise ArchiveSafetyError(f"Unsafe ZIP member name: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or pure.parts[0].endswith(":"):
        raise ArchiveSafetyError(f"Unsafe ZIP member path: {name}")
    mode = member.external_attr >> 16
    if stat.S_IFMT(mode) == stat.S_IFLNK:
        raise ArchiveSafetyError(f"ZIP symbolic links are not allowed: {name}")
    if member.flag_bits & 0x1:
        raise ArchiveSafetyError(f"Encrypted ZIP members are not allowed: {name}")
    target = (destination / Path(*pure.parts)).resolve()
    try:
        target.relative_to(destination.resolve())
    except ValueError as exc:
        raise ArchiveSafetyError(f"ZIP member escapes extraction root: {name}") from exc
    return target


def safe_extract_zip(archive_path: Path, destination: Path) -> list[str]:
    """Extract a package ZIP only after all members pass structural safety checks."""

    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ArchiveSafetyError(f"ZIP extraction directory must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(names) != len(set(names)):
            raise ArchiveSafetyError("ZIP contains duplicate member names.")
        targets = [_validated_member_path(destination, item) for item in members]
        for member, target in zip(members, targets, strict=True):
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    return names


__all__ = [
    "ArchiveSafetyError",
    "FIXED_ZIP_TIMESTAMP",
    "collect_kit_files",
    "safe_extract_zip",
    "write_deterministic_zip",
]
