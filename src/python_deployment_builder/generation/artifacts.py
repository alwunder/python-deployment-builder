"""Validate developer-supplied wheels without importing or executing their contents."""

from __future__ import annotations

import csv
import io
import stat
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.utils import canonicalize_name, parse_wheel_filename

from python_deployment_builder.generation.acquisition import PreparationError, sha256_file
from python_deployment_builder.models import ApprovedArtifact, DeploymentPlan
from python_deployment_builder.planning.index import wheel_matches


def parse_artifact_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name.strip() or not raw_path.strip():
        raise PreparationError("Artifact values must use DISTRIBUTION=C:\\path\\package.whl.")
    return canonicalize_name(name.strip()), Path(raw_path.strip()).expanduser()


def _safe_wheel_members(bundle: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = bundle.infolist()
    for member in members:
        path = PurePosixPath(member.filename.replace("\\", "/"))
        file_type = (member.external_attr >> 16) & 0o170000
        if (
            path.is_absolute()
            or ".." in path.parts
            or member.flag_bits & 0x1
            or file_type == stat.S_IFLNK
            or member.file_size > 256 * 1024 * 1024
        ):
            raise PreparationError(f"Wheel contains an unsafe member: {member.filename}")
    return members


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
            members = _safe_wheel_members(bundle)
            names = [item.filename for item in members]
            if len(names) != len(set(names)) or bundle.testzip() is not None:
                raise PreparationError(
                    f"Wheel archive entries are duplicated or corrupt: {path.name}"
                )
            metadata_members = [
                item
                for item in members
                if PurePosixPath(item.filename).name == "METADATA"
                and ".dist-info" in PurePosixPath(item.filename).parent.name
            ]
            if len(metadata_members) != 1:
                raise PreparationError(
                    f"Wheel must contain exactly one dist-info/METADATA file: {path.name}"
                )
            metadata_member = metadata_members[0]
            dist_info = PurePosixPath(metadata_member.filename).parent
            wheel_name = str(dist_info / "WHEEL")
            record_name = str(dist_info / "RECORD")
            if wheel_name not in names or record_name not in names:
                raise PreparationError(
                    f"Wheel is missing required WHEEL or RECORD metadata: {path.name}"
                )
            metadata = BytesParser().parsebytes(bundle.read(metadata_member))
            wheel_metadata = BytesParser().parsebytes(bundle.read(wheel_name))
            record_rows = list(
                csv.reader(io.StringIO(bundle.read(record_name).decode("utf-8")))
            )
            recorded_paths = {row[0] for row in record_rows if row}
            if not set(names) <= recorded_paths:
                raise PreparationError(f"Wheel RECORD is incomplete: {path.name}")
    except zipfile.BadZipFile as exc:
        raise PreparationError(f"Malformed wheel archive: {path.name}") from exc

    metadata_name = metadata.get("Name", "")
    metadata_version = metadata.get("Version", "")
    if canonicalize_name(metadata_name) != requested_name:
        raise PreparationError(
            f"Wheel metadata name mismatch: expected {requested_name}, received {metadata_name}."
        )
    if metadata_version != requirement.version:
        raise PreparationError(
            f"Wheel metadata version mismatch: expected {requirement.version}, "
            f"received {metadata_version}."
        )
    declared_tags = set(wheel_metadata.get_all("Tag", []))
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
