"""Non-executing validation of a staged deployment kit."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from python_deployment_builder.models import (
    DeploymentManifest,
    ManualValidationItem,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationFinalState,
    ValidationHost,
    ValidationReport,
)

HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
WINDOWS_ABSOLUTE = re.compile(r"(?i)[a-z]:\\(?:users|home)\\[^\r\n\"]+")
OBVIOUS_SECRET = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*bearer\s+[a-z0-9._-]{12,}|sk-[a-z0-9_-]{16,})"
)
FORBIDDEN_SHELL = ("powershell.exe", "pwsh.exe", "executionpolicy")
TEXT_SUFFIXES = {".bat", ".cmd", ".json", ".py", ".txt"}
SECRET_FILENAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "token.json",
    ".pypirc",
    "pip.ini",
}


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
        path = root / "deployment" / "wheels" / artifact.filename
        if not path.is_file() or _sha256(path) != artifact.sha256:
            artifact_failures.append(artifact.filename)
    checks.append(
        _check(
            "APPROVED_ARTIFACT_HASHES",
            not artifact_failures,
            "Approved artifact files match their manifest hashes.",
            "Approved artifact files are missing or changed.",
            evidence=artifact_failures,
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
    entry_candidates = []
    candidate_roots = manifest.source_roots or [".", "src"]
    for source_root in candidate_roots:
        base = root if source_root == "." else root / source_root
        entry_candidates.extend(
            [base / module_relative.with_suffix(".py"), base / module_relative / "__init__.py"]
        )
    checks.append(
        _check(
            "ENTRY_POINT_STRUCTURE",
            bool(manifest.entry_point_module and manifest.entry_point_callable)
            and any(path.is_file() for path in entry_candidates),
            "The entry-point module is structurally present under a planned source root.",
            "The entry-point module is not structurally present under a planned source root.",
            evidence=[str(path.relative_to(root)) for path in entry_candidates],
        )
    )

    sync_extras: list[str] = []
    for index_arg, value in enumerate(manifest.sync_arguments[:-1]):
        if value == "--extra":
            sync_extras.append(manifest.sync_arguments[index_arg + 1])
    checks.append(
        _check(
            "SELECTED_EXTRAS",
            sorted(sync_extras) == sorted(manifest.selected_extras),
            "Selected extras exactly match the locked sync command.",
            "Selected extras and locked sync arguments differ.",
            evidence=[f"manifest={manifest.selected_extras}", f"sync={sync_extras}"],
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
    for name in root_bats:
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
    security_paths = [*root.glob("*.bat"), *(root / "deployment").rglob("*")]
    for path in security_paths:
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()
        forbidden.extend(f"{relative}: {item}" for item in FORBIDDEN_SHELL if item in lowered)
        if WINDOWS_ABSOLUTE.search(text):
            developer_paths.append(relative)
        if "setx" in lowered and "path" in lowered:
            permanent_path.append(relative)
        if "program files" in lowered and any(
            token in lowered for token in ("mkdir", "copy ", "write_text", "open(")
        ):
            program_files.append(relative)
        if OBVIOUS_SECRET.search(text):
            obvious_secrets.append(relative)
        for name in manifest.configuration_presence_names:
            value = os.environ.get(name)
            if value and len(value) >= 8 and value in text:
                obvious_secrets.append(relative)
    secret_files = [
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and (
            path.name.lower() in SECRET_FILENAMES
            or (path.name.lower().startswith(".env.") and path.name.lower() != ".env.example")
        )
    ]
    cache_files = [
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and (path.suffix.lower() in {".pyc", ".pyo"} or "__pycache__" in path.parts)
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
