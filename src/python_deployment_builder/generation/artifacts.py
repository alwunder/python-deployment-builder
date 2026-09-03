"""Validate developer-supplied wheels without importing or executing their contents."""

from __future__ import annotations

import configparser
import csv
import fnmatch
import io
import re
import stat
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from python_deployment_builder.generation.acquisition import PreparationError, sha256_file
from python_deployment_builder.models import (
    ApplicationArtifact,
    ApprovedArtifact,
    DeploymentPlan,
    RepositoryAssessment,
)
from python_deployment_builder.planning.index import wheel_matches

FORBIDDEN_APPLICATION_TEXT = (b"powershell.exe", b"pwsh.exe", b"executionpolicy")
WINDOWS_DEVELOPER_PATH = re.compile(rb"(?i)(?:[a-z]:\\(?:users|home)\\[^\r\n\"]+)")
SECRET_MEMBER_NAMES = {".env", "credentials.json", "secrets.json"}


def parse_artifact_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name.strip() or not raw_path.strip():
        raise PreparationError("Artifact values must use DISTRIBUTION=C:\\path\\package.whl.")
    return canonicalize_name(name.strip()), Path(raw_path.strip()).expanduser()


def _normalized_wheel_path(value: str) -> str:
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        raise PreparationError(f"Wheel contains an unsafe member: {value}")
    path = PurePosixPath(value)
    if not path.parts or ".." in path.parts:
        raise PreparationError(f"Wheel contains an unsafe member: {value}")
    return path.as_posix()


def _safe_wheel_members(bundle: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = bundle.infolist()
    seen: dict[str, str] = {}
    for member in members:
        normalized = _normalized_wheel_path(member.filename)
        file_type = (member.external_attr >> 16) & 0o170000
        if (
            member.flag_bits & 0x1
            or file_type == stat.S_IFLNK
            or member.file_size > 256 * 1024 * 1024
        ):
            raise PreparationError(f"Wheel contains an unsafe member: {member.filename}")
        collision_key = normalized.rstrip("/").casefold()
        if previous := seen.get(collision_key):
            raise PreparationError(
                "Wheel contains duplicate or conflicting archive paths: "
                f"{previous}, {member.filename}"
            )
        seen[collision_key] = member.filename
    return members


def _member_map(members: list[zipfile.ZipInfo]) -> dict[str, zipfile.ZipInfo]:
    return {_normalized_wheel_path(item.filename): item for item in members}


def _metadata_message(data: bytes, *, label: str, wheel: Path):
    message = BytesParser(policy=default).parsebytes(data)
    if message.defects:
        raise PreparationError(f"Malformed {label} in wheel: {wheel.name}")
    return message


def _validate_record(
    bundle: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    record_name: str,
    wheel: Path,
) -> None:
    try:
        rows = list(
            csv.reader(
                io.StringIO(bundle.read(members[record_name]).decode("utf-8")),
                strict=True,
            )
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise PreparationError(f"Malformed wheel RECORD: {wheel.name}") from exc
    recorded: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise PreparationError(f"Malformed wheel RECORD: {wheel.name}")
        normalized = _normalized_wheel_path(row[0])
        key = normalized.casefold()
        if key in recorded:
            raise PreparationError(f"Wheel RECORD contains duplicate paths: {wheel.name}")
        recorded[key] = (row[1], row[2])
    actual = {
        name.casefold()
        for name, member in members.items()
        if not member.is_dir()
        and not name.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s"))
    }
    recorded_names = set(recorded)
    if actual - recorded_names:
        raise PreparationError(f"Wheel RECORD is incomplete: {wheel.name}")
    if recorded_names - actual:
        raise PreparationError(f"Wheel RECORD references nonexistent files: {wheel.name}")
    record_row = recorded.get(record_name.casefold())
    if record_row is None or record_row != ("", ""):
        raise PreparationError(
            f"Wheel RECORD must record itself with a blank hash and size: {wheel.name}"
        )


def _dist_info_members(
    members: dict[str, zipfile.ZipInfo], wheel: Path
) -> tuple[str, str, str]:
    metadata_names = [
        name
        for name in members
        if name.endswith(".dist-info/METADATA") and len(PurePosixPath(name).parts) == 2
    ]
    if len(metadata_names) != 1:
        raise PreparationError(
            f"Wheel must contain exactly one dist-info/METADATA file: {wheel.name}"
        )
    metadata_name = metadata_names[0]
    dist_info = PurePosixPath(metadata_name).parent.as_posix()
    return metadata_name, f"{dist_info}/WHEEL", f"{dist_info}/RECORD"


def _require_core_metadata(message, *, label: str, wheel: Path) -> tuple[str, str]:
    metadata_versions = message.get_all("Metadata-Version", [])
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    if (
        len(metadata_versions) != 1
        or not re.fullmatch(r"\d+(?:\.\d+)+", metadata_versions[0].strip())
        or len(names) != 1
        or not names[0].strip()
        or len(versions) != 1
        or not versions[0].strip()
    ):
        raise PreparationError(f"Malformed {label} in wheel: {wheel.name}")
    return names[0].strip(), versions[0].strip()


def _require_wheel_metadata(message, *, wheel: Path) -> set[str]:
    wheel_versions = message.get_all("Wheel-Version", [])
    purelib = message.get_all("Root-Is-Purelib", [])
    tags = {value.strip() for value in message.get_all("Tag", []) if value.strip()}
    if (
        len(wheel_versions) != 1
        or not re.fullmatch(r"\d+(?:\.\d+)+", wheel_versions[0].strip())
        or len(purelib) != 1
        or purelib[0].strip().lower() not in {"true", "false"}
        or not tags
    ):
        raise PreparationError(f"Malformed WHEEL metadata: {wheel.name}")
    return tags


def _validate_application_security(
    bundle: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    wheel: Path,
) -> None:
    failures: list[str] = []
    for name, member in members.items():
        member_path = PurePosixPath(name)
        if member.is_dir() or ".dist-info" in member_path.parts:
            continue
        lowered_name = member_path.name.lower()
        if member_path.suffix.lower() == ".ps1" or lowered_name in SECRET_MEMBER_NAMES:
            failures.append(name)
            continue
        if member_path.suffix.lower() not in {".py", ".bat", ".cmd", ".json", ".txt"}:
            continue
        data = bundle.read(member)
        lowered = data.lower()
        if (
            any(value in lowered for value in FORBIDDEN_APPLICATION_TEXT)
            or WINDOWS_DEVELOPER_PATH.search(data)
            or (b"setx" in lowered and b"path" in lowered)
            or (
                b"program files" in lowered
                and any(value in lowered for value in (b"write", b"mkdir", b"open("))
            )
        ):
            failures.append(name)
    if failures:
        raise PreparationError(
            "Application wheel content violates deployment security policy: "
            + ", ".join(sorted(failures))
        )


def validate_approved_wheel(
    value: str,
    plan: DeploymentPlan,
) -> tuple[ApprovedArtifact, Path]:
    requested_name, path = parse_artifact_argument(value)
    path = path.resolve()
    if not path.is_file() or path.suffix.lower() != ".whl":
        raise PreparationError(f"Approved artifact must be an existing wheel file: {path}")
    try:
        filename_name, filename_version, _build, filename_tags = parse_wheel_filename(path.name)
    except ValueError as exc:
        raise PreparationError(f"Malformed wheel filename: {path.name}") from exc
    if canonicalize_name(str(filename_name)) != requested_name:
        raise PreparationError(
            f"Artifact name mismatch: option requested {requested_name}, filename contains "
            f"{filename_name}."
        )
    requirements = {
        canonicalize_name(item.package): item
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
    }
    requirement = requirements.get(requested_name)
    if requirement is None:
        raise PreparationError(
            f"No developer-wheel requirement exists for {requested_name} in this deployment plan."
        )
    if str(filename_version) != requirement.version:
        raise PreparationError(
            f"Artifact version mismatch for {requested_name}: expected {requirement.version}, "
            f"received {filename_version}."
        )
    if not wheel_matches(path.name, plan.runtime.python_version, plan.runtime.architecture):
        raise PreparationError(
            f"Wheel {path.name} is incompatible with CPython {plan.runtime.python_version} "
            f"on Windows {plan.runtime.architecture}."
        )

    try:
        with zipfile.ZipFile(path) as bundle:
            members = _member_map(_safe_wheel_members(bundle))
            if bundle.testzip() is not None:
                raise PreparationError(
                    f"Wheel archive entries are corrupt: {path.name}"
                )
            metadata_name, wheel_name, record_name = _dist_info_members(members, path)
            if wheel_name not in members or record_name not in members:
                raise PreparationError(
                    f"Wheel is missing required WHEEL or RECORD metadata: {path.name}"
                )
            metadata = _metadata_message(
                bundle.read(members[metadata_name]), label="METADATA", wheel=path
            )
            wheel_metadata = _metadata_message(
                bundle.read(members[wheel_name]), label="WHEEL", wheel=path
            )
            _validate_record(bundle, members, record_name, path)
    except zipfile.BadZipFile as exc:
        raise PreparationError(f"Malformed wheel archive: {path.name}") from exc

    metadata_name, metadata_version = _require_core_metadata(
        metadata, label="METADATA", wheel=path
    )
    if canonicalize_name(metadata_name) != requested_name:
        raise PreparationError(
            f"Wheel metadata name mismatch: expected {requested_name}, received {metadata_name}."
        )
    if metadata_version != requirement.version:
        raise PreparationError(
            f"Wheel metadata version mismatch: expected {requirement.version}, "
            f"received {metadata_version}."
        )
    declared_tags = _require_wheel_metadata(wheel_metadata, wheel=path)
    filename_tag_values = {str(item) for item in filename_tags}
    if not declared_tags or not filename_tag_values <= declared_tags:
        raise PreparationError(f"Wheel tag metadata does not match its filename: {path.name}")
    return (
        ApprovedArtifact(
            distribution_name=requested_name,
            version=requirement.version,
            filename=path.name,
            sha256=sha256_file(path),
            wheel_tags=sorted(str(item) for item in filename_tags),
        ),
        path,
    )


def validate_artifact_set(
    values: list[str], plan: DeploymentPlan
) -> list[tuple[ApprovedArtifact, Path]]:
    validated = [validate_approved_wheel(value, plan) for value in values]
    names = [item[0].distribution_name for item in validated]
    if len(names) != len(set(names)):
        raise PreparationError("Each developer artifact requirement may be supplied only once.")
    return validated


def validate_application_wheel(
    path: Path,
    assessment: RepositoryAssessment,
    plan: DeploymentPlan,
) -> tuple[ApplicationArtifact, Path]:
    """Validate the explicit first-party wheel required by package mode."""

    path = path.expanduser().resolve()
    expected_name = canonicalize_name(assessment.project.distribution_name or "")
    expected_version = assessment.project.version or ""
    if not expected_name or not expected_version:
        raise PreparationError(
            "Package mode requires authoritative project distribution and version metadata."
        )
    try:
        expected_version_value = Version(expected_version)
    except InvalidVersion as exc:
        raise PreparationError(
            f"Application authoritative project version is invalid: {expected_version!r}."
        ) from exc
    if not path.is_file() or path.suffix.lower() != ".whl":
        raise PreparationError(f"Application wheel must be an existing wheel file: {path}")
    try:
        filename_name, filename_version, _build, filename_tags = parse_wheel_filename(path.name)
    except ValueError as exc:
        raise PreparationError(f"Malformed application wheel filename: {path.name}") from exc
    if canonicalize_name(str(filename_name)) != expected_name:
        raise PreparationError(
            f"Application wheel name mismatch: expected {expected_name}, received "
            f"{filename_name}."
        )
    if filename_version != expected_version_value:
        raise PreparationError(
            f"Application wheel version mismatch: expected {expected_version}, received "
            f"{filename_version}."
        )
    if not wheel_matches(path.name, plan.runtime.python_version, plan.runtime.architecture):
        raise PreparationError(
            f"Application wheel {path.name} is incompatible with CPython "
            f"{plan.runtime.python_version} on Windows {plan.runtime.architecture}."
        )

    entry_point = plan.entry_point
    if entry_point is None:
        raise PreparationError("Package mode requires an authoritative application entry point.")
    try:
        with zipfile.ZipFile(path) as bundle:
            members = _member_map(_safe_wheel_members(bundle))
            names = set(members)
            if bundle.testzip() is not None:
                raise PreparationError(
                    f"Application wheel entries are corrupt: {path.name}"
                )
            metadata_name, wheel_name, record_name = _dist_info_members(members, path)
            dist_info = PurePosixPath(metadata_name).parent
            entry_points_name = f"{dist_info.as_posix()}/entry_points.txt"
            for required in (wheel_name, record_name, entry_points_name):
                if required not in names:
                    raise PreparationError(
                        f"Application wheel is missing {required}: {path.name}"
                    )
            metadata = _metadata_message(
                bundle.read(members[metadata_name]), label="METADATA", wheel=path
            )
            wheel_metadata = _metadata_message(
                bundle.read(members[wheel_name]), label="WHEEL", wheel=path
            )
            _validate_record(bundle, members, record_name, path)

            metadata_distribution, metadata_version = _require_core_metadata(
                metadata, label="METADATA", wheel=path
            )
            if canonicalize_name(metadata_distribution) != expected_name:
                raise PreparationError("Application wheel METADATA distribution name is wrong.")
            try:
                metadata_version_value = Version(metadata_version)
            except InvalidVersion as exc:
                raise PreparationError(
                    f"Application wheel METADATA version is invalid: {metadata_version!r}."
                ) from exc
            if metadata_version_value != expected_version_value:
                raise PreparationError("Application wheel METADATA version is wrong.")
            declared_tags = _require_wheel_metadata(wheel_metadata, wheel=path)
            filename_tag_values = {str(item) for item in filename_tags}
            if not declared_tags or not filename_tag_values <= declared_tags:
                raise PreparationError(
                    f"Application wheel tag metadata does not match its filename: {path.name}"
                )
            if wheel_metadata.get("Root-Is-Purelib", "").strip().lower() != "true":
                raise PreparationError(
                    "Application wheels containing platform/native installation content require "
                    "explicit future project evidence and are not accepted by package mode."
                )

            cache_members = [
                name
                for name in names
                if name.lower().endswith((".pyc", ".pyo"))
                or any(
                    re.fullmatch(r"__pycache__(?:\s*\(\d+\))?", part, re.IGNORECASE)
                    for part in PurePosixPath(name).parts
                )
            ]
            native_members = [
                name
                for name in names
                if PurePosixPath(name).suffix.lower()
                in {".dll", ".pyd", ".so", ".dylib", ".exe", ".lib"}
            ]
            if cache_members:
                raise PreparationError(
                    "Application wheel contains Python runtime cache files: "
                    + ", ".join(cache_members)
                )
            if native_members:
                raise PreparationError(
                    "Application wheel contains unexpected native binaries: "
                    + ", ".join(native_members)
                )
            _validate_application_security(bundle, members, path)

            parser = configparser.ConfigParser(interpolation=None)
            parser.optionxform = str
            parser.read_string(bundle.read(members[entry_points_name]).decode("utf-8-sig"))
            entry_group = "gui_scripts" if entry_point.kind == "gui" else "console_scripts"
            installed_target = parser.get(
                entry_group,
                entry_point.name,
                fallback="",
            ).strip()
            if installed_target != entry_point.target:
                raise PreparationError(
                    "Application wheel entry point disagrees with authoritative metadata: "
                    f"expected {entry_point.name} = {entry_point.target}, received "
                    f"{installed_target or 'missing'}."
                )
            module_path = PurePosixPath(*entry_point.module.split("."))
            module_candidates = {
                str(module_path.with_suffix(".py")),
                str(module_path / "__init__.py"),
            }
            if not module_candidates.intersection(names):
                raise PreparationError(
                    "Application wheel does not contain its authoritative entry-point module: "
                    f"{entry_point.module}"
                )

            for package, patterns in assessment.project.package_data.items():
                if package == "*":
                    continue
                package_prefix = PurePosixPath(*package.split("."))
                package_members = []
                for name in names:
                    member_path = PurePosixPath(name)
                    try:
                        package_members.append(str(member_path.relative_to(package_prefix)))
                    except ValueError:
                        continue
                for pattern in patterns:
                    if not any(fnmatch.fnmatchcase(name, pattern) for name in package_members):
                        raise PreparationError(
                            "Application wheel is missing declared package data for "
                            f"{package}: {pattern}"
                        )
    except (zipfile.BadZipFile, UnicodeDecodeError, configparser.Error) as exc:
        raise PreparationError(f"Malformed application wheel: {path.name}") from exc

    return (
        ApplicationArtifact(
            distribution_name=expected_name,
            version=expected_version,
            filename=path.name,
            sha256=sha256_file(path),
            wheel_tags=sorted(str(item) for item in filename_tags),
            entry_point_name=entry_point.name,
            entry_point_target=entry_point.target,
        ),
        path,
    )
