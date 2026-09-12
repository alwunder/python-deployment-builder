"""Non-executing validation of a staged deployment kit."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from python_deployment_builder.backends.uv_managed import uv_sync_arguments
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import (
    configured_secret_values,
    installed_wheel_member_paths,
    validate_application_requires_dist,
    validate_application_wheel_content_policy,
    validate_approved_artifact_lock_identity,
    validate_approved_requires_dist,
    validate_combined_wheel_installation_paths,
    validate_wheel_installation_layout,
    validate_wheel_metadata_semantics,
    validate_wheel_static_safety,
    validate_wheel_target_compatibility,
)
from python_deployment_builder.generation.manifest import effective_configuration_secret_names
from python_deployment_builder.generation.structural import (
    approved_artifacts_by_path,
    manifest_artifact_wheel_path,
    trusted_artifact_wheel_paths,
)
from python_deployment_builder.models import (
    DeploymentManifest,
    ManualValidationItem,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationFinalState,
    ValidationHost,
    ValidationReport,
)
from python_deployment_builder.planning.lockfile import identify_uv_lock_root_name, inspect_uv_lock
from python_deployment_builder.security_policy import (
    FORBIDDEN_SHELL,
    TextContentEncodingError,
    decode_security_text,
    is_secret_filename,
    is_textual_content,
    text_security_findings,
)

HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PYTHON_CACHE_DIRECTORY = re.compile(r"^__pycache__(?:\s*\(\d+\))?$", re.IGNORECASE)


class KitValidationError(ValueError):
    """The supplied path is not a readable generated deployment kit."""


def _host() -> ValidationHost:
    return ValidationHost(
        operating_system=platform.system(),
        windows_version=platform.version() if platform.system() == "Windows" else None,
        architecture=platform.machine(),
        hostname=socket.gethostname(),
        username=os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
    )


def _check(
    code: str,
    condition: bool,
    success: str,
    failure: str,
    *,
    evidence: list[str] | None = None,
) -> ValidationCheckResult:
    return ValidationCheckResult(
        code=code,
        phase="static",
        status=ValidationCheckStatus.PASS if condition else ValidationCheckStatus.FAIL,
        detail=success if condition else failure,
        evidence=evidence or [],
    )


def _safe_kit_path(root: Path, relative: str) -> Path | None:
    candidate = (root / Path(relative)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _safe_manifest_artifact_path(root: Path, directory: str, filename: str) -> Path | None:
    """Return a contained manifest-owned wheel path without touching unsafe names."""

    relative = manifest_artifact_wheel_path(directory, filename)
    return _safe_kit_path(root, relative) if relative is not None else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(root: Path) -> DeploymentManifest:
    path = root / "deployment" / "manifest.json"
    try:
        return DeploymentManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise KitValidationError(f"Deployment manifest is missing: {path}") from exc
    except (OSError, ValidationError, ValueError) as exc:
        raise KitValidationError(f"Deployment manifest is invalid: {exc}") from exc


def _static_lock_root_name(root: Path, manifest: DeploymentManifest) -> str | None:
    """Find the staged lock root without re-assessing source packaging metadata."""

    try:
        lock_name = identify_uv_lock_root_name(root)
        with (root / "pyproject.toml").open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, ValueError):
        return None
    if lock_name is None:
        return None
    project = document.get("project")
    name = project.get("name") if isinstance(project, dict) else None
    names = [lock_name]
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return None
        names.insert(0, name)
    if manifest.application_artifact is not None:
        names.insert(0, manifest.application_artifact.distribution_name)
    try:
        if len({canonicalize_name(value, validate=True) for value in names}) != 1:
            return None
    except ValueError:
        return None
    return names[0]


def _static_lock_plan(root: Path, manifest: DeploymentManifest):
    """Build the transient staged-lock proof context used by artifact validators."""

    application_name = _static_lock_root_name(root, manifest)
    if application_name is None:
        raise PreparationError(
            "Staged-lock artifact validation cannot identify the root application."
        )
    graph = inspect_uv_lock(
        root,
        application_name,
        manifest.python_version,
        manifest.architecture,
        manifest.selected_extras,
    )
    if not graph.inspected:
        detail = "; ".join(graph.limitations) or "uv.lock could not be inspected."
        raise PreparationError(
            "Staged-lock artifact validation requires an inspected uv.lock: "
            f"{detail}"
        )
    return SimpleNamespace(
        runtime=SimpleNamespace(
            python_version=manifest.python_version,
            architecture=manifest.architecture,
        ),
        lock_graph=graph,
    )


def _manual_gui_checks(manifest: DeploymentManifest) -> list[ManualValidationItem]:
    checks = [
        ManualValidationItem(
            instruction=f"Double-click Run {manifest.application_display_name}.bat."
        ),
        ManualValidationItem(instruction="Confirm first-run setup completes without elevation."),
        ManualValidationItem(instruction="Confirm the application GUI opens."),
        ManualValidationItem(instruction="Exercise one representative core application workflow."),
        ManualValidationItem(instruction="Close the GUI and launch it again."),
        ManualValidationItem(instruction="Confirm the second launch uses the fast path."),
        ManualValidationItem(instruction="Run Diagnose and confirm the environment is current."),
    ]
    if manifest.project_write_probe_required:
        checks.append(
            ManualValidationItem(
                instruction="Confirm the planned project/output location is writable."
            )
        )
    for runtime in manifest.external_runtimes:
        checks.append(
            ManualValidationItem(
                instruction=(
                    f"Confirm Diagnose reports {runtime.name} and exercise the "
                    f"{runtime.feature or 'affected'} feature."
                )
            )
        )
    return checks


def validate_static_kit(kit_root: Path, *, dry_run: bool = False) -> ValidationReport:
    """Validate kit structure and fingerprints without executing kit or target code."""

    root = kit_root.resolve()
    manifest = _load_manifest(root)
    checks: list[ValidationCheckResult] = []

    checks.append(
        _check(
            "APPLICATION_ID_CONSISTENT",
            manifest.application_id in manifest.runtime_paths.application_root,
            "Application ID is consistent with the per-user runtime path.",
            "Application ID does not match the per-user runtime path.",
        )
    )

    application_artifact_failures: list[str] = []
    application_wheel: Path | None = None
    if manifest.deployment_mode == "package":
        if manifest.application_artifact is None:
            application_artifact_failures.append("manifest application artifact is missing")
        else:
            application_wheel = _safe_manifest_artifact_path(
                root, "application", manifest.application_artifact.filename
            )
            if (
                application_wheel is None
                or not application_wheel.is_file()
                or _sha256(application_wheel) != manifest.application_artifact.sha256
            ):
                application_artifact_failures.append(
                    f"unsafe application artifact filename: "
                    f"{manifest.application_artifact.filename}"
                    if application_wheel is None
                    else manifest.application_artifact.filename
                )
    elif manifest.application_artifact is not None:
        application_artifact_failures.append(
            "source mode unexpectedly declares an application wheel"
        )
    checks.append(
        _check(
            "APPLICATION_ARTIFACT_HASH",
            not application_artifact_failures,
            "The first-party application artifact matches its manifest SHA-256.",
            "The first-party application artifact is missing, changed, or misplaced.",
            evidence=application_artifact_failures,
        )
    )
    package_source_paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.relative_to(root).parts[0] != "deployment"
        and path.name not in {"pyproject.toml", "uv.lock"}
        and path.suffix.lower() != ".bat"
    )
    package_isolation_ok = (
        manifest.deployment_mode != "package"
        or (
            not manifest.source_roots
            and "PYTHONPATH" not in manifest.runtime_environment
            and not package_source_paths
        )
    )
    checks.append(
        _check(
            "PACKAGE_SOURCE_ISOLATION",
            package_isolation_ok,
            "Package mode has no staged source roots or PYTHONPATH and launches the installed "
            "application artifact.",
            "Package mode contains staged source content or source import configuration.",
            evidence=package_source_paths,
        )
    )
    checks.append(
        _check(
            "RUNTIME_METADATA_PRESENT",
            bool(
                manifest.python_version
                and manifest.uv_version
                and HEX_SHA256.fullmatch(manifest.uv_archive_sha256)
            ),
            "Python, pinned uv, and uv archive checksum metadata are present.",
            "Python version, uv version, or uv archive checksum metadata is invalid.",
        )
    )

    referenced_missing: list[str] = []
    referenced_unsafe: list[str] = []
    for relative in manifest.referenced_files:
        path = _safe_kit_path(root, relative)
        if path is None:
            referenced_unsafe.append(relative)
        elif not path.is_file():
            referenced_missing.append(relative)
    checks.append(
        _check(
            "MANIFEST_REFERENCES",
            not referenced_missing and not referenced_unsafe,
            "All manifest-referenced files exist beneath the kit root.",
            "Manifest references are missing or unsafe.",
            evidence=[
                *(f"missing: {item}" for item in referenced_missing),
                *(f"unsafe: {item}" for item in referenced_unsafe),
            ],
        )
    )

    index_path = root / "deployment" / "generated-files.json"
    index_error: str | None = None
    index: dict = {}
    try:
        parsed = json.loads(index_path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or not isinstance(parsed.get("files"), list):
            raise ValueError("expected an object containing a files list")
        index = parsed
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        index_error = str(exc)
    checks.append(
        _check(
            "GENERATED_INDEX_VALID",
            index_error is None and index.get("application_id") == manifest.application_id,
            "The generated-file index parses and matches the application ID.",
            "The generated-file index is invalid or belongs to another application.",
            evidence=[index_error] if index_error else [],
        )
    )
    hash_failures: list[str] = []
    indexed_paths: set[str] = set()
    if index_error is None:
        for item in index["files"]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                hash_failures.append("malformed generated-file entry")
                continue
            indexed_paths.add(item["path"])
            path = _safe_kit_path(root, item["path"])
            expected = item.get("sha256")
            if (
                path is None
                or not path.is_file()
                or not isinstance(expected, str)
                or not HEX_SHA256.fullmatch(expected)
                or _sha256(path) != expected
            ):
                hash_failures.append(item["path"])
    checks.append(
        _check(
            "GENERATED_FILE_HASHES",
            index_error is None and not hash_failures,
            "All indexed generated and staged files match their recorded SHA-256 values.",
            "One or more indexed files are missing, malformed, or changed.",
            evidence=hash_failures,
        )
    )
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != index_path
    }
    unexpected_paths = sorted(actual_paths - indexed_paths)
    checks.append(
        _check(
            "NO_UNINDEXED_STAGED_FILES",
            index_error is None and not unexpected_paths,
            "Every staged file is covered by the generated-file integrity index.",
            "One or more staged files were added after generation or are not indexed.",
            evidence=unexpected_paths,
        )
    )
    approved_path_failures: list[str] = []
    try:
        approved_by_relative = approved_artifacts_by_path(manifest.approved_artifacts)
    except PreparationError as exc:
        approved_by_relative = {}
        approved_path_failures.append(str(exc))
    checks.append(
        _check(
            "APPROVED_ARTIFACT_PATH_UNIQUENESS",
            not approved_path_failures,
            "Each approved artifact owns one safe, Windows-distinct wheel path.",
            "Approved artifacts have unsafe or duplicate materialization paths.",
            evidence=approved_path_failures,
        )
    )
    trusted_wheels = trusted_artifact_wheel_paths(manifest)
    secret_scanability_failures: list[str] = []
    try:
        secret_values = configured_secret_values(effective_configuration_secret_names(manifest))
    except PreparationError as exc:
        secret_values = ()
        secret_scanability_failures.append(str(exc))
    checks.append(
        _check(
            "CONFIGURED_SECRET_SCANABILITY",
            not secret_scanability_failures,
            "Current configured secret values can be scanned reliably when present.",
            "A current configured secret value is too short for reliable content scanning.",
            evidence=secret_scanability_failures,
        )
    )
    unvalidated_wheels = sorted(
        path
        for path in actual_paths
        if PurePosixPath(path).suffix.lower() == ".whl" and path not in trusted_wheels
    )
    checks.append(
        _check(
            "NO_UNVALIDATED_STAGED_WHEELS",
            not unvalidated_wheels,
            "Every staged wheel is an exact manifest-declared artifact.",
            "A staged wheel is not an exact manifest-declared artifact.",
            evidence=unvalidated_wheels,
        )
    )

    metadata_hash_failures = []
    for name, expected in (
        ("pyproject.toml", manifest.pyproject_sha256),
        ("uv.lock", manifest.lockfile_sha256),
    ):
        path = root / name
        if not path.is_file() or _sha256(path) != expected:
            metadata_hash_failures.append(name)
    checks.append(
        _check(
            "PROJECT_METADATA_HASHES",
            not metadata_hash_failures,
            "Staged pyproject.toml and uv.lock match the deployment manifest.",
            "Staged project metadata does not match the deployment manifest.",
            evidence=metadata_hash_failures,
        )
    )

    bundled_path = root / "deployment" / "bootstrap" / "uv.exe"
    bundled_ok = manifest.bootstrap_mode != "bundled_uv" or (
        bundled_path.is_file()
        and bool(manifest.bundled_uv_sha256)
        and _sha256(bundled_path) == manifest.bundled_uv_sha256
    )
    checks.append(
        _check(
            "BUNDLED_UV_HASH",
            bundled_ok,
            "Bundled uv.exe matches its manifest SHA-256.",
            "Bundled uv.exe is missing or does not match its manifest SHA-256.",
        )
    )

    artifact_failures: list[str] = []
    for artifact in manifest.approved_artifacts:
        path = _safe_manifest_artifact_path(root, "wheels", artifact.filename)
        if path is None or not path.is_file() or _sha256(path) != artifact.sha256:
            artifact_failures.append(
                f"unsafe approved artifact filename: {artifact.filename}"
                if path is None
                else artifact.filename
            )
    checks.append(
        _check(
            "APPROVED_ARTIFACT_HASHES",
            not artifact_failures,
            "Approved artifact files match their manifest hashes.",
            "Approved artifact files are missing or changed.",
            evidence=artifact_failures,
        )
    )
    wheel_layout_failures: list[str] = []
    safe_trusted_wheel_paths: list[Path] = []
    for relative in sorted(trusted_wheels):
        path = _safe_kit_path(root, relative)
        if path is None or not path.is_file():
            continue
        try:
            validate_wheel_installation_layout(path)
            safe_trusted_wheel_paths.append(path)
        except PreparationError as exc:
            wheel_layout_failures.append(f"{relative}: {exc}")
    checks.append(
        _check(
            "WHEEL_INSTALLATION_LAYOUT",
            not wheel_layout_failures,
            "Manifest-declared wheels have safe archive and installation layouts.",
            "A manifest-declared wheel has an unsafe archive or installation layout.",
            evidence=wheel_layout_failures,
        )
    )
    expected_wheel_identities: dict[str, tuple[str, str]] = {}
    if manifest.application_artifact is not None and (
        relative := manifest_artifact_wheel_path(
            "application", manifest.application_artifact.filename
        )
    ):
        expected_wheel_identities[relative] = (
            manifest.application_artifact.distribution_name,
            manifest.application_artifact.version,
        )
    for relative, artifact in approved_by_relative.items():
        expected_wheel_identities[relative] = (
            artifact.distribution_name,
            artifact.version,
        )
    wheel_metadata_failures: list[str] = []
    wheel_metadata_by_path = {}
    for path in safe_trusted_wheel_paths:
        relative = path.relative_to(root).as_posix()
        try:
            metadata = validate_wheel_metadata_semantics(path)
            expected = expected_wheel_identities.get(relative)
            if expected is None:
                raise PreparationError("Wheel is not an exact manifest-owned artifact.")
            expected_name, expected_version = expected
            try:
                expected_version_value = Version(expected_version)
            except InvalidVersion as exc:
                raise PreparationError(
                    f"Manifest wheel version is invalid: {path.name}"
                ) from exc
            if canonicalize_name(expected_name) != metadata.distribution_name:
                raise PreparationError(
                    f"Wheel METADATA name does not match manifest artifact: {path.name}"
                )
            if expected_version_value != metadata.version:
                raise PreparationError(
                    f"Wheel METADATA version does not match manifest artifact: {path.name}"
                )
            wheel_metadata_by_path[path] = metadata
        except PreparationError as exc:
            wheel_metadata_failures.append(f"{relative}: {exc}")
    checks.append(
        _check(
            "WHEEL_METADATA_SEMANTICS",
            not wheel_metadata_failures,
            "Manifest-declared wheels have valid metadata matching their filenames and manifests.",
            "A manifest-declared wheel has invalid or mismatched installer metadata.",
            evidence=wheel_metadata_failures,
        )
    )
    wheel_target_failures: list[str] = []
    for path in safe_trusted_wheel_paths:
        try:
            metadata = validate_wheel_metadata_semantics(path)
            validate_wheel_target_compatibility(
                path,
                python_version=manifest.python_version,
                architecture=manifest.architecture,
                requires_python=metadata.requires_python,
            )
        except PreparationError as exc:
            wheel_target_failures.append(f"{path.relative_to(root)}: {exc}")
    checks.append(
        _check(
            "WHEEL_TARGET_COMPATIBILITY",
            not wheel_target_failures,
            "Manifest-declared wheels are compatible with the planned Windows target.",
            "A manifest-declared wheel is incompatible with the planned Windows target.",
            evidence=wheel_target_failures,
        )
    )
    application_content_failures: list[str] = []
    if application_wheel is not None and application_wheel in safe_trusted_wheel_paths:
        try:
            validate_application_wheel_content_policy(application_wheel)
        except PreparationError as exc:
            application_content_failures.append(str(exc))
    checks.append(
        _check(
            "APPLICATION_WHEEL_CONTENT_POLICY",
            not application_content_failures,
            "The first-party application wheel satisfies the pure-Python content policy.",
            "The first-party application wheel violates the pure-Python content policy.",
            evidence=application_content_failures,
        )
    )
    static_plan = None
    static_lock_failures: list[str] = []
    try:
        static_plan = _static_lock_plan(root, manifest)
    except (PreparationError, InvalidVersion, ValueError) as exc:
        static_lock_failures.append(str(exc))

    approved_identity_failures = list(static_lock_failures)
    if static_plan is not None:
        approved_identities: list[tuple[str, Version]] = []
        for artifact in manifest.approved_artifacts:
            try:
                artifact_identity = (
                    canonicalize_name(artifact.distribution_name),
                    Version(artifact.version),
                )
                validate_approved_artifact_lock_identity(
                    artifact.distribution_name, artifact.version, static_plan
                )
            except (PreparationError, InvalidVersion, ValueError) as exc:
                approved_identity_failures.append(
                    f"{artifact.distribution_name}=={artifact.version}: {exc}"
                )
            else:
                if artifact_identity in approved_identities:
                    approved_identity_failures.append(
                        "Manifest repeats an approved artifact lock identity: "
                        f"{artifact.distribution_name}=={artifact.version}."
                    )
                approved_identities.append(artifact_identity)
        for requirement in static_plan.lock_graph.artifact_requirements:
            try:
                requirement_version = Version(requirement.version)
            except InvalidVersion:
                approved_identity_failures.append(
                    f"Invalid staged-lock artifact requirement version: "
                    f"{requirement.package}=={requirement.version}"
                )
                continue
            matching = []
            for artifact in manifest.approved_artifacts:
                try:
                    artifact_version = Version(artifact.version)
                except InvalidVersion:
                    continue
                if (
                    canonicalize_name(artifact.distribution_name)
                    == canonicalize_name(requirement.package)
                    and artifact_version == requirement_version
                ):
                    matching.append(artifact)
            if len(matching) != 1:
                approved_identity_failures.append(
                    "Staged-lock developer artifact requirement does not have exactly one "
                    f"manifest-approved wheel: {requirement.package}=={requirement.version}."
                )
    checks.append(
        _check(
            "APPROVED_ARTIFACT_LOCK_IDENTITY",
            not approved_identity_failures,
            "Manifest-approved artifacts exactly match staged-lock developer requirements.",
            "Manifest-approved artifacts and staged-lock developer requirements disagree.",
            evidence=approved_identity_failures,
        )
    )

    wheel_dependency_failures: list[str] = []
    dependency_wheels = [
        path
        for path in safe_trusted_wheel_paths
        if path in wheel_metadata_by_path and wheel_metadata_by_path[path].requires_dist
    ]
    if dependency_wheels:
        if static_plan is None:
            wheel_dependency_failures.extend(static_lock_failures)
        else:
            application_relative = (
                manifest_artifact_wheel_path(
                    "application", manifest.application_artifact.filename
                )
                if manifest.application_artifact is not None
                else None
            )
            for path in dependency_wheels:
                relative = path.relative_to(root).as_posix()
                try:
                    metadata = wheel_metadata_by_path[path]
                    if relative == application_relative:
                        if manifest.application_artifact is None:
                            raise PreparationError("Application wheel is not manifest-owned.")
                        validate_application_requires_dist(
                            metadata.requires_dist,
                            static_plan,
                            canonicalize_name(manifest.application_artifact.distribution_name),
                            metadata.version,
                        )
                        continue
                    artifact = approved_by_relative.get(relative)
                    if artifact is None:
                        raise PreparationError("Wheel is not an exact manifest-owned artifact.")
                    validate_approved_requires_dist(
                        metadata.requires_dist,
                        static_plan,
                        canonicalize_name(artifact.distribution_name),
                        metadata.version,
                    )
                except (PreparationError, InvalidVersion, ValueError) as exc:
                    wheel_dependency_failures.append(f"{relative}: {exc}")
    checks.append(
        _check(
            "WHEEL_DEPENDENCY_COMPATIBILITY",
            not wheel_dependency_failures,
            "Manifest-declared wheel dependencies are proven against the staged uv.lock.",
            "A manifest-declared wheel dependency is not proven by the staged uv.lock.",
            evidence=wheel_dependency_failures,
        )
    )
    wheel_security_failures: list[str] = []
    for path in safe_trusted_wheel_paths:
        try:
            validate_wheel_static_safety(path, configured_secret_values=secret_values)
        except PreparationError as exc:
            wheel_security_failures.append(f"{path.relative_to(root)}: {exc}")
    checks.append(
        _check(
            "WHEEL_SECURITY",
            not wheel_security_failures,
            "Manifest-declared wheels pass member security validation.",
            "A manifest-declared wheel violates member security validation.",
            evidence=wheel_security_failures,
        )
    )
    combined_wheel_failures: list[str] = []
    if not wheel_layout_failures:
        try:
            validate_combined_wheel_installation_paths(safe_trusted_wheel_paths)
        except PreparationError as exc:
            combined_wheel_failures.append(str(exc))
    checks.append(
        _check(
            "WHEEL_INSTALLATION_COLLISIONS",
            not combined_wheel_failures,
            "Manifest-declared wheels have no combined installed-path collisions.",
            "Manifest-declared wheels have colliding installed destinations.",
            evidence=combined_wheel_failures,
        )
    )

    missing_source_roots = [
        item
        for item in manifest.source_roots
        if not (root if item == "." else root / item).is_dir()
    ]
    checks.append(
        _check(
            "SOURCE_ROOTS",
            (manifest.deployment_mode != "source" or bool(manifest.source_roots))
            and not missing_source_roots,
            "All planned source roots exist in the staged kit.",
            "One or more planned source roots are missing.",
            evidence=missing_source_roots,
        )
    )
    module_relative = Path(*manifest.entry_point_module.split("."))
    entry_candidates: list[Path] = []
    entry_evidence: list[str] = []
    entry_present = False
    if manifest.deployment_mode == "source":
        for source_root in manifest.source_roots:
            base = root if source_root == "." else root / source_root
            entry_candidates.extend(
                [
                    base / module_relative.with_suffix(".py"),
                    base / module_relative / "__init__.py",
                ]
            )
        entry_present = any(path.is_file() for path in entry_candidates)
        entry_evidence = [str(path.relative_to(root)) for path in entry_candidates]
    elif application_wheel is not None and application_wheel.is_file():
        member_base = "/".join(manifest.entry_point_module.split("."))
        member_candidates = {f"{member_base}.py", f"{member_base}/__init__.py"}
        try:
            with zipfile.ZipFile(application_wheel) as bundle:
                members = {
                    PurePosixPath(member.filename).as_posix(): member
                    for member in bundle.infolist()
                }
                entry_present = bool(
                    member_candidates.intersection(
                        installed_wheel_member_paths(members, application_wheel)
                    )
                )
        except (zipfile.BadZipFile, PreparationError):
            entry_present = False
        entry_evidence = sorted(member_candidates)
    checks.append(
        _check(
            "ENTRY_POINT_STRUCTURE",
            bool(manifest.entry_point_module and manifest.entry_point_callable)
            and entry_present,
            "The entry-point module is structurally present in its deployment mode.",
            "The entry-point module is not structurally present in its deployment mode.",
            evidence=entry_evidence,
        )
    )

    expected_sync_arguments = uv_sync_arguments(
        python_version=manifest.python_version,
        selected_extras=manifest.selected_extras,
        approved_artifact_names=[
            artifact.distribution_name for artifact in manifest.approved_artifacts
        ],
    )
    checks.append(
        _check(
            "SYNC_ARGUMENTS_CONTRACT",
            manifest.sync_arguments == expected_sync_arguments,
            "Runtime sync arguments exactly match the immutable uv-managed contract.",
            "Runtime sync arguments differ from the immutable uv-managed contract.",
            evidence=[
                f"expected={expected_sync_arguments}",
                f"actual={manifest.sync_arguments}",
            ],
        )
    )

    root_bats = [path.name for path in root.glob("*.bat")]
    expected_bat_prefixes = ("Run ", "Repair ", "Diagnose ")
    missing_bats = [
        prefix.rstrip()
        for prefix in expected_bat_prefixes
        if not any(name.startswith(prefix) for name in root_bats)
    ]
    helper_relatives = (
        "deployment/bootstrap/bootstrap.cmd",
        "deployment/runtime/runtime_common.py",
        "deployment/runtime/manage.py",
        "deployment/runtime/launch.py",
        "deployment/runtime/diagnostics.py",
    )
    missing_helpers = [item for item in helper_relatives if not (root / item).is_file()]
    checks.append(
        _check(
            "LAUNCHERS_AND_HELPERS",
            not missing_bats and not missing_helpers,
            "Run, Repair, Diagnose, bootstrap, and runtime helpers are present.",
            "Required launchers or runtime helpers are missing.",
            evidence=[
                *(f"missing BAT: {item}" for item in missing_bats),
                *(f"missing helper: {item}" for item in missing_helpers),
            ],
        )
    )
    bad_bat_structure = []
    generated_root_bats = {
        Path(item).name
        for item in manifest.referenced_files
        if "/" not in item and item.lower().endswith(".bat")
    }
    for name in root_bats:
        if name not in generated_root_bats:
            continue
        text = (root / name).read_text(encoding="utf-8", errors="replace").lower()
        if not text.startswith("@echo off") or "deployment\\bootstrap\\bootstrap.cmd" not in text:
            bad_bat_structure.append(name)
    checks.append(
        _check(
            "BAT_STRUCTURE",
            not bad_bat_structure,
            "Root BAT files are thin delegates to the generated CMD bootstrap.",
            "A root BAT file is not a plausible generated bootstrap delegate.",
            evidence=bad_bat_structure,
        )
    )

    ps1_files = [str(path.relative_to(root)) for path in root.rglob("*.ps1")]
    forbidden: list[str] = []
    developer_paths: list[str] = []
    permanent_path: list[str] = []
    program_files: list[str] = []
    obvious_secrets: list[str] = []
    undecodable_text: list[str] = []
    security_paths = {
        *(_safe_kit_path(root, relative) for relative in indexed_paths),
        *root.glob("*.bat"),
        *(root / "deployment").rglob("*"),
    }
    for path in security_paths:
        if path is None or not path.is_file():
            continue
        relative = str(path.relative_to(root))
        if path.suffix.lower() == ".whl":
            if relative in trusted_wheels:
                continue
            # The dedicated unvalidated-wheel check above owns this opaque
            # member; do not claim an ordinary text scan proved it safe.
            continue
        content = path.read_bytes()
        if not is_textual_content(Path(relative), content):
            continue
        try:
            text = decode_security_text(PurePosixPath(relative), content)
        except TextContentEncodingError:
            undecodable_text.append(relative)
            continue
        if text is None:
            continue
        findings = text_security_findings(
            text, configured_secret_values=secret_values
        )
        if "forbidden_shell" in findings:
            lowered = text.lower()
            forbidden.extend(
                f"{relative}: {item}" for item in FORBIDDEN_SHELL if item in lowered
            )
        if "developer_path" in findings:
            developer_paths.append(relative)
        if "permanent_path" in findings:
            permanent_path.append(relative)
        if "program_files_write" in findings:
            program_files.append(relative)
        if {"obvious_secret", "configured_secret"} & findings:
            obvious_secrets.append(relative)
    secret_files = [
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and is_secret_filename(path.name)
    ]
    cache_files = [
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower() in {".pyc", ".pyo"}
            or any(PYTHON_CACHE_DIRECTORY.fullmatch(part) for part in path.parts)
        )
    ]
    developer_state = [
        str(path.relative_to(root))
        for name in (".git", ".idea", "tests")
        if (path := root / name).exists()
    ]
    checks.extend(
        [
            _check(
                "NO_PS1_FILES",
                not ps1_files,
                "No .ps1 files exist.",
                ".ps1 files exist.",
                evidence=ps1_files,
            ),
            _check(
                "NO_POWERSHELL",
                not forbidden,
                "No prohibited PowerShell invocation exists in generated text.",
                "Prohibited PowerShell text was detected.",
                evidence=forbidden,
            ),
            _check(
                "NO_DEVELOPER_PATHS",
                not developer_paths,
                "No developer absolute path leaked into generated text.",
                "A developer absolute path leaked into generated text.",
                evidence=developer_paths,
            ),
            _check(
                "NO_PATH_MUTATION",
                not permanent_path,
                "No permanent PATH mutation is present.",
                "A permanent PATH mutation is present.",
                evidence=permanent_path,
            ),
            _check(
                "NO_PROGRAM_FILES_WRITE",
                not program_files,
                "No Program Files write target is present.",
                "A Program Files write target is present.",
                evidence=program_files,
            ),
            _check(
                "TEXT_SECURITY_DECODABLE",
                not undecodable_text,
                "All staged textual content is valid UTF-8/UTF-8-SIG for security scanning.",
                "Textual content cannot be security-scanned as UTF-8.",
                evidence=undecodable_text,
            ),
            _check(
                "NO_SECRET_CONTENT",
                not secret_files and not obvious_secrets,
                "No secret files or obvious secret values are staged.",
                "Secret material may be present in the staged kit.",
                evidence=[*secret_files, *obvious_secrets],
            ),
            _check(
                "NO_RUNTIME_CACHES",
                not cache_files,
                "No bytecode/runtime cache files are staged.",
                "Bytecode or runtime cache files are present in the staged kit.",
                evidence=cache_files,
            ),
            _check(
                "NO_DEVELOPER_STATE",
                not developer_state,
                "Git, IDE, and test-tree developer state is absent from the kit.",
                "Developer-only directories are present in the staged kit.",
                evidence=developer_state,
            ),
        ]
    )

    helper_text = "\n".join(
        (root / item).read_text(encoding="utf-8", errors="replace")
        for item in helper_relatives
        if (root / item).is_file()
    )
    checks.append(
        _check(
            "HELPER_INTERPRETER_POLICY",
            " -I " not in helper_text
            and "-B -E -s" in helper_text
            and '"-B"' in helper_text
            and '"-E"' in helper_text
            and '"-s"' in helper_text,
            "Generated helpers use -B -E -s, preserving sibling imports while excluding "
            "bytecode writes, PYTHON* configuration, and user site-packages.",
            "Generated helper interpreter flags are inconsistent or still use -I.",
        )
    )
    checks.append(
        _check(
            "RUNTIME_HELPERS_INDEPENDENT",
            "python_deployment_builder" not in helper_text,
            "Generated runtime helpers do not import Python Deployment Builder.",
            "A generated runtime helper imports Python Deployment Builder.",
        )
    )
    checks.append(
        _check(
            "PROJECT_WRITE_POLICY",
            not manifest.project_write_probe_required
            or (
                (root / "deployment/runtime/launch.py").is_file()
                and "probe_project_write" in (
                    root / "deployment/runtime/launch.py"
                ).read_text(encoding="utf-8", errors="replace")
            ),
            "The planned project-write requirement is represented by the launch helper.",
            "The manifest requires a project-write probe but the launch helper lacks it.",
        )
    )
    if manifest.system_certs:
        bootstrap_text = (root / "deployment/bootstrap/bootstrap.cmd").read_text(
            encoding="utf-8", errors="replace"
        )
        common_text = (root / "deployment/runtime/runtime_common.py").read_text(
            encoding="utf-8", errors="replace"
        )
        checks.append(
            _check(
                "SYSTEM_CERTS_PROPAGATION",
                "UV_SYSTEM_CERTS=true" in bootstrap_text
                and 'result["UV_SYSTEM_CERTS"] = "true"' in common_text,
                "The Windows system-certificate policy reaches bootstrap and managed uv "
                "operations.",
                "The system-certificate policy is not consistently propagated.",
            )
        )

    failed = any(item.status == ValidationCheckStatus.FAIL for item in checks)
    final_state = ValidationFinalState.FAILED if failed else ValidationFinalState.STATIC_VALID
    return ValidationReport(
        generated_at=datetime.now(UTC),
        application_id=manifest.application_id,
        application_display_name=manifest.application_display_name,
        deployment_fingerprint=manifest.deployment_fingerprint,
        kit_root=str(root),
        validation_mode="static",
        dry_run=dry_run,
        host=_host(),
        static_checks=checks,
        manual_gui_checks=(
            _manual_gui_checks(manifest)
            if manifest.entry_point_kind == "gui"
            else []
        ),
        final_state=final_state,
    )


__all__ = ["KitValidationError", "validate_static_kit"]
