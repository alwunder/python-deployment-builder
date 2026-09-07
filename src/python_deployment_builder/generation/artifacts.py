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
from packaging.specifiers import InvalidSpecifier
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from python_deployment_builder.analysis.resources import (
    package_surface_resolved,
    resolve_package_data_members,
    resolve_packaged_python_sources,
)
from python_deployment_builder.generation.acquisition import PreparationError, sha256_file
from python_deployment_builder.models import (
    ApplicationArtifact,
    ApprovedArtifact,
    DeploymentPlan,
    RepositoryAssessment,
)
from python_deployment_builder.planning.index import (
    TargetMarkerApplicability,
    TargetMarkerEnvironmentError,
    target_marker_applicability,
    target_marker_applies,
    wheel_matches,
)
from python_deployment_builder.planning.policies import (
    MinorPythonCompatibility,
    minor_python_compatibility,
)
from python_deployment_builder.security_policy import (
    TextContentEncodingError,
    decode_security_text,
    is_secret_filename,
    is_textual_wheel_member,
    text_security_findings,
)

MAX_WHEEL_MEMBERS = 10_000
MAX_WHEEL_MEMBER_SIZE = 256 * 1024 * 1024
MAX_WHEEL_TOTAL_UNCOMPRESSED_SIZE = 512 * 1024 * 1024

_WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_DEVICE_BASENAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)


def parse_artifact_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name.strip() or not raw_path.strip():
        raise PreparationError("Artifact values must use DISTRIBUTION=C:\\path\\package.whl.")
    return canonicalize_name(name.strip()), Path(raw_path.strip()).expanduser()


def _windows_materializable_component(component: str) -> None:
    """Reject components Windows cannot create through ordinary file APIs."""

    if (
        not component
        or component.endswith((".", " "))
        or any(
            character in _WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS
            or character == "\x00"
            or 1 <= ord(character) <= 31
            for character in component
        )
    ):
        raise PreparationError(f"Wheel contains a Windows-invalid path component: {component!r}")
    # Windows reserves device basenames even when an ordinary-looking suffix
    # follows (for example CON.py or NUL.tar.gz).
    basename = component.split(".", 1)[0].upper()
    if basename in _WINDOWS_RESERVED_DEVICE_BASENAMES:
        raise PreparationError(f"Wheel contains a Windows-reserved path component: {component!r}")


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
    for component in path.parts:
        _windows_materializable_component(component)
    return path.as_posix()


def _validate_regular_file_path_collisions(
    paths: list[tuple[str, str]], *, domain: str
) -> None:
    """Reject Windows-equivalent file paths that cannot coexist on disk.

    ``paths`` contain materialized regular-file destinations and their archive
    provenance.  Archive paths and relocated ``purelib`` paths are different
    domains, but a file can never also be a component ancestor in either one.
    """

    regular_paths: dict[str, str] = {}
    for normalized, provenance in paths:
        collision_key = normalized.casefold()
        for index in range(1, len(PurePosixPath(normalized).parts)):
            ancestor = "/".join(PurePosixPath(normalized).parts[:index]).casefold()
            if previous := regular_paths.get(ancestor):
                raise PreparationError(
                    f"Wheel contains a regular-file ancestor collision in {domain} paths: "
                    f"{previous}, {provenance}"
                )
        for existing_key, existing_name in regular_paths.items():
            if existing_key.startswith(collision_key + "/"):
                raise PreparationError(
                    f"Wheel contains a regular-file ancestor collision in {domain} paths: "
                    f"{existing_name}, {provenance}"
                )
        regular_paths[collision_key] = provenance


def _safe_wheel_members(bundle: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = bundle.infolist()
    if len(members) > MAX_WHEEL_MEMBERS:
        raise PreparationError(f"Wheel contains too many archive members: {len(members)}")
    total_size = sum(member.file_size for member in members)
    if total_size > MAX_WHEEL_TOTAL_UNCOMPRESSED_SIZE:
        raise PreparationError("Wheel exceeds the maximum expanded archive size.")
    seen: dict[str, str] = {}
    regular_paths: list[tuple[str, str]] = []
    for member in members:
        normalized = _normalized_wheel_path(member.filename)
        file_type = (member.external_attr >> 16) & 0o170000
        if (
            member.flag_bits & 0x1
            or file_type == stat.S_IFLNK
            or member.file_size > MAX_WHEEL_MEMBER_SIZE
        ):
            raise PreparationError(f"Wheel contains an unsafe member: {member.filename}")
        collision_key = normalized.rstrip("/").casefold()
        if previous := seen.get(collision_key):
            raise PreparationError(
                "Wheel contains duplicate or conflicting archive paths: "
                f"{previous}, {member.filename}"
            )
        seen[collision_key] = member.filename
        if member.is_dir():
            continue
        regular_paths.append((normalized.rstrip("/"), member.filename))
    _validate_regular_file_path_collisions(regular_paths, domain="archive")
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


def _identity_directory_matches(
    directory: str,
    *,
    suffix: str,
    expected_name: str,
    expected_version: Version,
    wheel: Path,
) -> None:
    """Require an installed metadata directory to identify this wheel.

    Wheel writers normally use one normalized ``name-version`` separator, but
    consumers must tolerate historical spellings that retain punctuation in
    the distribution name. Try every separator and accept only one semantic
    interpretation rather than assuming a dash cannot occur in either part.
    """

    if not directory.endswith(suffix):  # pragma: no cover - caller invariant
        raise PreparationError(f"Malformed wheel identity directory: {wheel.name}")
    stem = directory[: -len(suffix)]
    candidates: list[tuple[str, Version]] = []
    for index, character in enumerate(stem):
        if character != "-":
            continue
        candidate_name = stem[:index]
        candidate_version = stem[index + 1 :]
        if not candidate_name or not candidate_version:
            continue
        try:
            parsed_version = Version(candidate_version)
        except InvalidVersion:
            continue
        if (
            canonicalize_name(candidate_name) == expected_name
            and parsed_version == expected_version
        ):
            candidates.append((candidate_name, parsed_version))
    if len(candidates) != 1:
        raise PreparationError(
            f"Wheel {suffix} directory identity does not match its filename: {wheel.name}"
        )


def _dist_info_members(
    members: dict[str, zipfile.ZipInfo], wheel: Path
) -> tuple[str, str, str]:
    try:
        filename_name, filename_version, _build, _tags = parse_wheel_filename(wheel.name)
    except ValueError as exc:  # pragma: no cover - validated by callers first
        raise PreparationError(f"Malformed wheel filename: {wheel.name}") from exc
    expected_name = canonicalize_name(str(filename_name))
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
    dist_info_roots = {
        path.parts[0]
        for name in members
        if (path := PurePosixPath(name)).parts and path.parts[0].endswith(".dist-info")
    }
    if dist_info_roots != {dist_info}:
        raise PreparationError(
            f"Wheel must contain exactly one distribution dist-info directory: {wheel.name}"
        )
    _identity_directory_matches(
        dist_info,
        suffix=".dist-info",
        expected_name=expected_name,
        expected_version=filename_version,
        wheel=wheel,
    )
    data_roots = {
        path.parts[0]
        for name in members
        if (path := PurePosixPath(name)).parts and path.parts[0].endswith(".data")
    }
    if len(data_roots) > 1:
        raise PreparationError(
            f"Wheel contains multiple distribution data directories: {wheel.name}"
        )
    for data_root in data_roots:
        _identity_directory_matches(
            data_root,
            suffix=".data",
            expected_name=expected_name,
            expected_version=filename_version,
            wheel=wheel,
        )
    return metadata_name, f"{dist_info}/WHEEL", f"{dist_info}/RECORD"


def installed_wheel_member_destinations(
    members: dict[str, zipfile.ZipInfo], wheel: Path
) -> dict[str, str]:
    """Map every materialized site-packages destination after wheel relocation.

    The authoritative root ``.dist-info`` tree participates in collision
    accounting.  ``purelib`` members are relocated by installers into that
    same namespace; other data schemes remain outside this M6.1 application
    surface.  The caller has already validated the wheel's ``.data`` identity.
    """

    installed: dict[str, str] = {}
    destinations: list[tuple[str, str]] = []
    for name, member in members.items():
        if member.is_dir():
            continue
        path = PurePosixPath(name)
        destination: PurePosixPath | None = path
        if path.parts[0].endswith(".data"):
            if len(path.parts) < 3 or path.parts[1] != "purelib":
                # scripts/headers/data have no site-packages application
                # representation; platlib is outside the pure-Python contract.
                if len(path.parts) >= 2 and path.parts[1] == "platlib":
                    raise PreparationError(
                        "Application wheel uses .data/platlib, which is not accepted by the "
                        f"pure-Python package-mode contract: {wheel.name}"
                    )
                destination = None
            else:
                destination = PurePosixPath(*path.parts[2:])
                if any(part.endswith(".dist-info") for part in destination.parts):
                    raise PreparationError(
                        "Wheel .data/purelib content may not create an installed dist-info "
                        f"tree: {name}"
                    )
        if destination is None or not destination.parts:
            continue
        normalized = destination.as_posix()
        key = normalized.casefold()
        if previous := installed.get(key):
            raise PreparationError(
                "Wheel contains colliding installed member paths: "
                f"{previous}, {name}"
            )
        installed[key] = normalized
        destinations.append((normalized, name))
    _validate_regular_file_path_collisions(destinations, domain="installed")
    return installed


def installed_wheel_member_paths(
    members: dict[str, zipfile.ZipInfo], wheel: Path
) -> set[str]:
    """Return the validated installed paths that form application surface.

    Metadata still contributes to installed-destination collision detection,
    but never becomes Python/package-data application surface.
    """

    return {
        destination
        for destination in installed_wheel_member_destinations(members, wheel).values()
        if not PurePosixPath(destination).parts[0].endswith(".dist-info")
    }


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
    """Require a precision-safe Requires-Python proof for a minor-only runtime."""

    values = metadata.get_all("Requires-Python", [])
    if not values:
        return
    if len(values) != 1 or not values[0].strip():
        raise PreparationError(f"Malformed Requires-Python metadata in wheel: {wheel.name}")
    constraint = values[0].strip()
    try:
        compatibility = minor_python_compatibility(plan.runtime.python_version, constraint)
    except (InvalidSpecifier, ValueError) as exc:
        raise PreparationError(
            f"Malformed Requires-Python metadata in wheel: {wheel.name}"
        ) from exc
    if compatibility == MinorPythonCompatibility.INCOMPATIBLE:
        raise PreparationError(
            f"Wheel Requires-Python {constraint!r} is incompatible with selected Python "
            f"{plan.runtime.python_version}."
        )
    if compatibility == MinorPythonCompatibility.UNPROVABLE:
        raise PreparationError(
            f"Wheel Requires-Python {constraint!r} cannot be proven for minor-only selected "
            f"Python {plan.runtime.python_version}."
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
        content = bundle.read(member)
        if not is_textual_wheel_member(member_path, content):
            continue
        try:
            text = decode_security_text(member_path, content)
        except TextContentEncodingError as exc:
            raise PreparationError(str(exc)) from exc
        if text is None:
            continue
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
    requirements = [
        item
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
        if canonicalize_name(item.package) == requested_name
    ]
    versions = {item.version for item in requirements}
    if not requirements:
        raise PreparationError(
            f"No developer-wheel requirement exists for {requested_name} in this deployment plan."
        )
    target_possible_versions = {
        dependency.version
        for dependency in (plan.lock_graph.dependencies if plan.lock_graph else [])
        if canonicalize_name(dependency.name) == requested_name
    }
    if len(target_possible_versions) > 1:
        raise PreparationError(
            "Developer artifact substitution is ambiguous for target-possible locked versions: "
            f"{requested_name} ({', '.join(sorted(target_possible_versions))})."
        )
    if len(versions) != 1:
        raise PreparationError(
            "Developer artifact substitution is ambiguous for target-possible locked versions: "
            f"{requested_name} ({', '.join(sorted(versions))})."
        )
    requirement = requirements[0]
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
            # Dependency wheels are installed by the same Windows runtime.
            # Validate relocated site-packages destinations even though they
            # have no first-party application-surface completeness contract.
            installed_wheel_member_destinations(members, path)
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
    for requirement in plan.lock_graph.artifact_requirements if plan.lock_graph else []:
        validate_artifact_substitution_target(requirement.package, plan)
    validated = [validate_approved_wheel(value, plan) for value in values]
    names = [item[0].distribution_name for item in validated]
    if len(names) != len(set(names)):
        raise PreparationError("Each developer artifact requirement may be supplied only once.")
    return validated


def validate_artifact_substitution_target(package: str, plan: DeploymentPlan) -> None:
    """Reject a stale plan that would replace conditional versions by one wheel."""

    canonical_name = canonicalize_name(package)
    versions = {
        dependency.version
        for dependency in (plan.lock_graph.dependencies if plan.lock_graph else [])
        if canonicalize_name(dependency.name) == canonical_name
    }
    if len(versions) > 1:
        raise PreparationError(
            "Developer artifact substitution is ambiguous for target-possible locked versions: "
            f"{package} ({', '.join(sorted(versions))})."
        )


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


def _target_possible_dependencies(graph, canonical_name: str):
    """Return direct selected-target candidates for one application dependency."""

    return sorted(
        (
            dependency
            for dependency in graph.dependencies
            if dependency.direct and canonicalize_name(dependency.name) == canonical_name
        ),
        key=lambda dependency: (Version(dependency.version), dependency.version),
    )


def _direct_dependency_presence_proven(
    graph, plan: DeploymentPlan, application_name: str, canonical_name: str
) -> None:
    """Require a definitely-applicable root lock edge for wheel metadata presence."""

    selected_extras = {canonicalize_name(extra) for extra in graph.selected_extras}
    matching = []
    unprovable: list[str] = []
    malformed: list[str] = []
    for edge in graph.edges:
        if (
            canonicalize_name(edge.from_package) != application_name
            or canonicalize_name(edge.to_package) != canonical_name
        ):
            continue
        if edge.selected_extra and canonicalize_name(edge.selected_extra) not in selected_extras:
            continue
        matching.append(edge)
        try:
            applicability = target_marker_applicability(
                edge.marker,
                plan.runtime.python_version,
                plan.runtime.architecture,
                extra=edge.selected_extra or "",
            )
        except TargetMarkerEnvironmentError as exc:
            malformed.append(str(exc))
            continue
        if applicability == TargetMarkerApplicability.APPLIES:
            return
        if applicability == TargetMarkerApplicability.UNPROVABLE:
            unprovable.append(edge.marker or "<unknown marker>")
    if unprovable or malformed:
        detail = "; ".join([*unprovable, *malformed])
        raise PreparationError(
            "Application wheel Requires-Dist presence cannot be proven from a definitely "
            f"applicable direct locked dependency edge for {canonical_name}: {detail}."
        )
    if matching:
        raise PreparationError(
            "Application wheel Requires-Dist is absent from the selected locked environment: "
            f"{canonical_name}; no direct locked dependency edge definitely applies."
        )
    raise PreparationError(
        "Application wheel Requires-Dist is absent from the selected locked environment: "
        f"{canonical_name}; no direct locked dependency edge exists."
    )


def _validate_dependency_extra_closure(requirement: Requirement, graph, candidates) -> None:
    """Prove a wheel dependency's requested extras are activated by the selected lock graph."""

    requested = {canonicalize_name(extra) for extra in requirement.extras}
    name = canonicalize_name(requirement.name)
    without_activation = [
        dependency.version
        for dependency in candidates
        if not requested
        <= {canonicalize_name(extra) for extra in dependency.requested_dependency_extras}
    ]
    if without_activation:
        raise PreparationError(
            "Application wheel Requires-Dist dependency extra is not activated for every "
            "target-possible locked version: "
            f"{requirement.name}[{','.join(sorted(requested))}]. Missing activation: "
            + ", ".join(sorted(set(without_activation)))
        )
    without_declaration = [
        dependency.version
        for dependency in candidates
        if not requested
        <= {canonicalize_name(extra) for extra in dependency.available_dependency_extras}
    ]
    if without_declaration:
        raise PreparationError(
            "Application wheel Requires-Dist dependency extra is not declared by every "
            "target-possible locked version: "
            f"{requirement.name}[{','.join(sorted(requested))}]. Missing declaration: "
            + ", ".join(sorted(set(without_declaration)))
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
    metadata, plan: DeploymentPlan, application_name: str, application_version: Version
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
            if requirement.url:
                raise PreparationError(
                    "Application wheel self Requires-Dist direct references are not "
                    "statically provable: "
                    f"{requirement.name}."
                )
            if requirement.extras:
                raise PreparationError(
                    "Application wheel self Requires-Dist extras are not statically provable: "
                    f"{requirement.name}[{','.join(sorted(requirement.extras))}]."
                )
            if application_version not in requirement.specifier:
                raise PreparationError(
                    "Application wheel self Requires-Dist is incompatible with its own version: "
                    f"{requirement}. Application version: {application_version}."
                )
            continue
        if requirement.url:
            raise PreparationError(
                "Application wheel Requires-Dist direct references are not provable against "
                f"the selected locked environment: {requirement.name}."
            )
        try:
            _direct_dependency_presence_proven(graph, plan, application_name, name)
            candidates = _target_possible_dependencies(graph, name)
        except InvalidVersion as exc:
            raise PreparationError(
                "Selected lock graph has an invalid version for application wheel "
                f"Requires-Dist {requirement.name}."
            ) from exc
        if not candidates:
            raise PreparationError(
                "Application wheel Requires-Dist is absent from the selected locked "
                f"environment: {requirement.name}."
            )
        versions = sorted({candidate.version for candidate in candidates})
        incompatible = sorted(
            {
                candidate.version
                for candidate in candidates
                if Version(candidate.version) not in requirement.specifier
            }
        )
        if incompatible:
            raise PreparationError(
                "Application wheel Requires-Dist cannot be proven for every target-possible "
                f"locked version: {requirement}. Possible versions: {', '.join(versions)}. "
                f"incompatible possible versions: {', '.join(incompatible)}."
            )
        if requirement.extras:
            _validate_dependency_extra_closure(requirement, graph, candidates)


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
    if not package_surface_resolved(assessment.project, repository_root) or any(
        item.code == "PACKAGING_SURFACE_UNRESOLVED" for item in assessment.risks
    ):
        backend = assessment.project.build_backend or "no build backend"
        raise PreparationError(
            "Application wheel validation requires an authoritative Python packaging-surface "
            f"model; {backend} is not modeled by M6.1."
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
            installed_names = installed_wheel_member_paths(members, path)
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
                _validate_application_requires_dist(
                    metadata, plan, expected_name, expected_version_value
                )
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
            if not module_candidates.intersection(installed_names):
                raise PreparationError(
                    "Application wheel does not contain its authoritative entry-point module: "
                    f"{entry_point.module}"
                )

            source_root = repository_root
            if source_root is None:
                candidate = Path(assessment.repository.source).expanduser()
                source_root = candidate if candidate.is_dir() else None
            if (
                assessment.project.package_data
                or assessment.project.packages
                or assessment.project.py_modules
            ) and source_root is None:
                raise PreparationError(
                    "Application wheel packaging-surface validation requires the assessed "
                    "repository root."
                )
            expected_members = {
                member.installed_member_path
                for member in resolve_package_data_members(source_root, assessment.project)
            } if source_root is not None else set()
            missing_members = sorted(expected_members - installed_names)
            if missing_members:
                raise PreparationError(
                    "Application wheel is missing concrete declared package data: "
                    + ", ".join(missing_members)
                )
            expected_python_members = {
                member.installed_member_path
                for member in resolve_packaged_python_sources(source_root, assessment.project)
            } if source_root is not None else set()
            missing_python_members = sorted(expected_python_members - installed_names)
            if missing_python_members:
                raise PreparationError(
                    "Application wheel is missing authoritative first-party Python source: "
                    + ", ".join(missing_python_members)
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
