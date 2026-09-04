"""Validate developer-supplied wheels without importing or executing their contents."""

from __future__ import annotations

import base64
import binascii
import configparser
import csv
import hashlib
import hmac
import io
import os
import re
import stat
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from python_deployment_builder.analysis.resources import resolve_package_data_members
from python_deployment_builder.generation.acquisition import PreparationError, sha256_file
from python_deployment_builder.models import (
    ApplicationArtifact,
    ApprovedArtifact,
    DeploymentPlan,
    RepositoryAssessment,
)
from python_deployment_builder.planning.index import (
    TargetMarkerEnvironmentError,
    target_marker_applies,
    wheel_matches,
)
from python_deployment_builder.planning.policies import python_satisfies
from python_deployment_builder.security_policy import (
    is_secret_filename,
    is_textual_wheel_member,
    text_security_findings,
)


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
    for name, member in members.items():
        if member.is_dir() or name.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s")):
            continue
        if name == record_name:
            continue
        recorded_hash, recorded_size = recorded[name.casefold()]
        if not recorded_size.isascii() or not recorded_size.isdecimal():
            raise PreparationError(f"Wheel RECORD has an invalid size for {name}: {wheel.name}")
        try:
            expected_size = int(recorded_size)
        except ValueError as exc:  # pragma: no cover - guarded by isdecimal
            raise PreparationError(
                f"Wheel RECORD has an invalid size for {name}: {wheel.name}"
            ) from exc
        if expected_size != member.file_size:
            raise PreparationError(f"Wheel RECORD size mismatch for {name}: {wheel.name}")
        algorithm, separator, encoded_digest = recorded_hash.partition("=")
        if (
            not separator
            or algorithm not in {"sha256", "sha384", "sha512"}
            or not encoded_digest
            or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded_digest)
        ):
            raise PreparationError(f"Wheel RECORD has an invalid hash for {name}: {wheel.name}")
        try:
            expected_digest = base64.b64decode(
                encoded_digest + "=" * (-len(encoded_digest) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise PreparationError(
                f"Wheel RECORD has an invalid hash for {name}: {wheel.name}"
            ) from exc
        digest = hashlib.new(algorithm)
        with bundle.open(member) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        if not hmac.compare_digest(digest.digest(), expected_digest):
            raise PreparationError(f"Wheel RECORD hash mismatch for {name}: {wheel.name}")


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
    wheel_version = wheel_versions[0].strip() if len(wheel_versions) == 1 else ""
    if (
        len(wheel_versions) != 1
        or not re.fullmatch(r"\d+(?:\.\d+)+", wheel_version)
        or len(purelib) != 1
        or purelib[0].strip().lower() not in {"true", "false"}
        or not tags
    ):
        raise PreparationError(f"Malformed WHEEL metadata: {wheel.name}")
    if int(wheel_version.split(".", 1)[0]) != 1:
        raise PreparationError(
            f"Unsupported Wheel-Version {wheel_version!r}: {wheel.name}. "
            "PDB supports Wheel major version 1."
        )
    return tags


def _validate_requires_python(metadata, plan: DeploymentPlan, wheel: Path) -> None:
    """Apply the planner's conservative minor-as-.0 policy to wheel Core Metadata."""

    values = metadata.get_all("Requires-Python", [])
    if not values:
        return
    if len(values) != 1 or not values[0].strip():
        raise PreparationError(f"Malformed Requires-Python metadata in wheel: {wheel.name}")
    constraint = values[0].strip()
    try:
        SpecifierSet(constraint)
    except InvalidSpecifier as exc:
        raise PreparationError(
            f"Malformed Requires-Python metadata in wheel: {wheel.name}"
        ) from exc
    if not python_satisfies(plan.runtime.python_version, constraint):
        raise PreparationError(
            f"Wheel Requires-Python {constraint!r} is incompatible with selected Python "
            f"{plan.runtime.python_version}."
        )


def _validate_application_security(
    bundle: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    *,
    configured_secret_values: tuple[str, ...] = (),
) -> None:
    failures: list[str] = []
    for name, member in members.items():
        member_path = PurePosixPath(name)
        if member.is_dir():
            continue
        if member_path.suffix.lower() == ".ps1" or is_secret_filename(member_path.name):
            failures.append(name)
            continue
        if not is_textual_wheel_member(member_path):
            continue
        text = bundle.read(member).decode("utf-8", errors="replace")
        if text_security_findings(
            text, configured_secret_values=configured_secret_values
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
    _validate_requires_python(metadata, plan, path)
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


def _application_requirement_applies(requirement: Requirement, plan: DeploymentPlan) -> bool:
    """Evaluate Core Metadata markers against the planned Windows target, not this host."""

    marker = str(requirement.marker) if requirement.marker else None
    if marker is None:
        return True
    selected_extras = plan.lock_graph.selected_extras if plan.lock_graph else []
    try:
        return any(
            target_marker_applies(
                marker,
                plan.runtime.python_version,
                plan.runtime.architecture,
                extra=extra,
            )
            for extra in ["", *selected_extras]
        )
    except TargetMarkerEnvironmentError as exc:
        raise PreparationError(
            "Application wheel Requires-Dist marker cannot be proven for the selected "
            f"target: {requirement}. {exc}"
        ) from exc


def _validate_dependency_extra_closure(requirement: Requirement, graph) -> None:
    """Prove a wheel dependency's requested extras are activated by the selected lock graph."""

    requested = set(requirement.extras)
    name = canonicalize_name(requirement.name)
    candidates = [
        dependency
        for dependency in graph.dependencies
        if canonicalize_name(dependency.name) == name
        and Version(dependency.version) in requirement.specifier
        and requested <= set(dependency.requested_dependency_extras)
    ]
    if not candidates:
        raise PreparationError(
            "Application wheel Requires-Dist dependency extra cannot be proven against the "
            f"selected locked environment: {requirement.name}[{','.join(sorted(requested))}]"
        )
    if not any(requested <= set(item.available_dependency_extras) for item in candidates):
        raise PreparationError(
            "Application wheel Requires-Dist dependency extra is not declared by the locked "
            f"dependency: {requirement.name}[{','.join(sorted(requested))}]"
        )

    known = {canonicalize_name(item.name) for item in graph.dependencies}
    pending = [name]
    visited: set[str] = set()
    while pending:
        parent = pending.pop()
        if parent in visited:
            continue
        visited.add(parent)
        for edge in graph.edges:
            if not edge.applicable or canonicalize_name(edge.from_package) != parent:
                continue
            child = canonicalize_name(edge.to_package)
            if child not in known:
                extras = ",".join(sorted(requested))
                raise PreparationError(
                    "Application wheel Requires-Dist dependency extra closure is incomplete "
                    f"in the selected locked environment: {requirement.name}[{extras}] "
                    f"requires {edge.to_package}."
                )
            pending.append(child)


def _validate_application_requires_dist(
    metadata, plan: DeploymentPlan, application_name: str
) -> None:
    """Prove every applicable first-party wheel requirement is in the selected lock graph."""

    raw_requirements = metadata.get_all("Requires-Dist", [])
    if not raw_requirements:
        return
    graph = plan.lock_graph
    if graph is None or not graph.inspected:
        raise PreparationError(
            "Application wheel Requires-Dist validation requires an inspected selected uv.lock "
            "dependency graph."
        )
    locked: dict[str, list[str]] = {}
    for dependency in graph.dependencies:
        locked.setdefault(canonicalize_name(dependency.name), []).append(dependency.version)
    for raw in raw_requirements:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement as exc:
            raise PreparationError(
                f"Application wheel has malformed Requires-Dist metadata: {raw!r}."
            ) from exc
        if not _application_requirement_applies(requirement, plan):
            continue
        name = canonicalize_name(requirement.name)
        if name == application_name:
            continue
        if requirement.url:
            raise PreparationError(
                "Application wheel Requires-Dist direct references are not provable against "
                f"the selected locked environment: {requirement.name}."
            )
        versions = locked.get(name, [])
        if not versions:
            raise PreparationError(
                "Application wheel Requires-Dist is absent from the selected locked "
                f"environment: {requirement.name}."
            )
        try:
            compatible = any(Version(version) in requirement.specifier for version in versions)
        except InvalidVersion as exc:
            raise PreparationError(
                "Selected lock graph has an invalid version for application wheel "
                f"Requires-Dist {requirement.name}: {versions!r}."
            ) from exc
        if not compatible:
            raise PreparationError(
                "Application wheel Requires-Dist is incompatible with the selected locked "
                f"environment: {requirement}. Locked versions: {', '.join(sorted(versions))}."
            )
        if requirement.extras:
            _validate_dependency_extra_closure(requirement, graph)


def validate_application_wheel(
    path: Path,
    assessment: RepositoryAssessment,
    plan: DeploymentPlan,
    *,
    repository_root: Path | None = None,
    validate_locked_dependencies: bool = True,
) -> tuple[ApplicationArtifact, Path]:
    """Validate the explicit first-party wheel required by package mode.

    Structural artifact checks are always performed.  Requires-Dist is evaluated only
    when the caller has a current inspected lock graph to compare against.
    """

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
    if entry_point.declared_group not in {"console_scripts", "gui_scripts"}:
        raise PreparationError(
            "Package mode requires an authoritative entry-point packaging group; "
            "PDB will not infer it from launch classification."
        )
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
            _validate_requires_python(metadata, plan, path)
            if validate_locked_dependencies:
                _validate_application_requires_dist(metadata, plan, expected_name)
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
            configured_secret_values = tuple(
                value
                for item in plan.configuration
                if item.secret and (value := os.environ.get(item.name)) is not None
            )
            _validate_application_security(
                bundle,
                members,
                configured_secret_values=configured_secret_values,
            )

            parser = configparser.ConfigParser(interpolation=None)
            parser.optionxform = str
            parser.read_string(bundle.read(members[entry_points_name]).decode("utf-8-sig"))
            installed_target = parser.get(
                entry_point.declared_group,
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

            source_root = repository_root
            if source_root is None:
                candidate = Path(assessment.repository.source).expanduser()
                source_root = candidate if candidate.is_dir() else None
            if assessment.project.package_data and source_root is None:
                raise PreparationError(
                    "Application wheel package-data validation requires the assessed "
                    "repository root."
                )
            expected_members = {
                member.installed_member_path
                for member in resolve_package_data_members(source_root, assessment.project)
            } if source_root is not None else set()
            missing_members = sorted(expected_members - names)
            if missing_members:
                raise PreparationError(
                    "Application wheel is missing concrete declared package data: "
                    + ", ".join(missing_members)
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
