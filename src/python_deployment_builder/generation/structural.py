"""Non-executing validation for rendered deployment output."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.models import (
    DeploymentManifest,
    FindingStatus,
    RiskFinding,
    RiskSeverity,
)

FORBIDDEN_TEXT = ("powershell.exe", "pwsh.exe", "executionpolicy")
WINDOWS_ABSOLUTE = re.compile(rb"(?i)(?:[a-z]:\\(?:users|home)\\[^\r\n\"]+)")


def _check(condition: bool, code: str, description: str) -> RiskFinding:
    return RiskFinding(
        code=code,
        title=code.replace("_", " ").title(),
        severity=RiskSeverity.INFO if condition else RiskSeverity.BLOCKING,
        status=FindingStatus.DETECTED,
        description=description,
    )


def validate_rendered_files(
    files: dict[str, bytes],
    manifest: DeploymentManifest,
    *,
    generated_paths: set[str],
    secret_values: list[str] | None = None,
) -> list[RiskFinding]:
    checks: list[RiskFinding] = []
    missing = sorted(set(manifest.referenced_files) - set(files))
    checks.append(
        _check(not missing, "MANIFEST_REFERENCES", f"Missing referenced files: {missing or 'none'}")
    )
    bundled = files.get("deployment/bootstrap/uv.exe")
    checks.append(
        _check(
            manifest.bootstrap_mode != "bundled_uv"
            or (
                bundled is not None
                and hashlib.sha256(bundled).hexdigest() == manifest.bundled_uv_sha256
            ),
            "BUNDLED_UV_FINGERPRINT",
            "Bundled uv.exe matches its deployment-manifest SHA-256.",
        )
    )
    artifact_hashes_ok = all(
        (
            data := files.get(f"deployment/wheels/{artifact.filename}")
        ) is not None
        and hashlib.sha256(data).hexdigest() == artifact.sha256
        for artifact in manifest.approved_artifacts
    )
    checks.append(
        _check(
            artifact_hashes_ok,
            "APPROVED_ARTIFACT_FINGERPRINTS",
            "Approved developer artifacts match their manifest SHA-256 values.",
        )
    )
    checks.append(
        _check(
            manifest.application_id in manifest.runtime_paths.application_root,
            "APPLICATION_ID_CONSISTENT",
            "Application ID matches its per-user runtime path.",
        )
    )
    checks.append(
        _check(
            bool(manifest.entry_point_module and manifest.entry_point_callable),
            "ENTRY_POINT_PRESENT",
            "Entry-point module and callable are present.",
        )
    )
    checks.append(
        _check(
            bool(manifest.lockfile_sha256),
            "LOCK_FINGERPRINT_PRESENT",
            "uv.lock is fingerprinted.",
        )
    )

    forbidden_hits: list[str] = []
    developer_path_hits: list[str] = []
    permanent_path_hits: list[str] = []
    program_files_hits: list[str] = []
    secret_hits: list[str] = []
    for relative in generated_paths:
        if PurePosixPath(relative).suffix.lower() not in {
            ".bat",
            ".cmd",
            ".json",
            ".py",
            ".txt",
        }:
            continue
        data = files.get(relative, b"")
        lowered = data.lower()
        for value in FORBIDDEN_TEXT:
            if value.encode() in lowered:
                forbidden_hits.append(f"{relative}:{value}")
        if WINDOWS_ABSOLUTE.search(data):
            developer_path_hits.append(relative)
        if b"setx" in lowered and b"path" in lowered:
            permanent_path_hits.append(relative)
        if b"program files" in lowered and (b"write" in lowered or b"mkdir" in lowered):
            program_files_hits.append(relative)
        for secret in secret_values or []:
            if len(secret) >= 8 and secret.encode("utf-8") in data:
                secret_hits.append(relative)
    ps1_files = [path for path in generated_paths if PurePosixPath(path).suffix.lower() == ".ps1"]
    runtime_builder_imports = [
        path
        for path in generated_paths
        if path.startswith("deployment/runtime/")
        and b"python_deployment_builder" in files.get(path, b"")
    ]
    checks.extend(
        [
            _check(not ps1_files, "NO_PS1_FILES", f"Forbidden script files: {ps1_files or 'none'}"),
            _check(
                not forbidden_hits,
                "NO_FORBIDDEN_SHELL",
                f"Forbidden shell references: {forbidden_hits or 'none'}",
            ),
            _check(
                not developer_path_hits,
                "NO_DEVELOPER_PATHS",
                f"Absolute developer paths: {developer_path_hits or 'none'}",
            ),
            _check(
                not permanent_path_hits,
                "NO_PATH_MUTATION",
                f"Permanent PATH mutations: {permanent_path_hits or 'none'}",
            ),
            _check(
                not program_files_hits,
                "NO_PROGRAM_FILES_WRITES",
                f"Program Files write targets: {program_files_hits or 'none'}",
            ),
            _check(
                not secret_hits,
                "NO_SECRET_VALUES",
                f"Secret values found in generated output: {secret_hits or 'none'}",
            ),
            _check(
                not runtime_builder_imports,
                "RUNTIME_INDEPENDENT",
                f"Runtime helpers importing the builder: {runtime_builder_imports or 'none'}",
            ),
        ]
    )
    for path in generated_paths:
        if path.lower().endswith(".bat"):
            text = files[path].decode("utf-8", errors="replace").lower()
            plausible = (
                text.startswith("@echo off")
                and "deployment\\bootstrap\\bootstrap.cmd" in text
            )
            checks.append(
                _check(plausible, "BAT_STRUCTURE", f"BAT structure checked: {path}")
            )
    failures = [item for item in checks if item.severity == RiskSeverity.BLOCKING]
    if failures:
        raise PreparationError(
            "Generated deployment failed structural validation: "
            + "; ".join(f"{item.code}: {item.description}" for item in failures)
        )
    return checks


def validate_written_files(output_root: Path, manifest: DeploymentManifest) -> None:
    for relative in manifest.referenced_files:
        path = (output_root / Path(relative)).resolve()
        try:
            path.relative_to(output_root.resolve())
        except ValueError as exc:
            raise PreparationError(f"Manifest references an unsafe path: {relative}") from exc
        if not path.is_file():
            raise PreparationError(
                f"Manifest-referenced file is missing after generation: {relative}"
            )
    manifest_path = output_root / "deployment" / "manifest.json"
    parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    if parsed.get("application_id") != manifest.application_id:
        raise PreparationError("Written deployment manifest application ID is inconsistent.")
