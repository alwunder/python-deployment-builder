"""Non-executing validation for rendered deployment output."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.models import (
    ApprovedArtifact,
    DeploymentManifest,
    FindingStatus,
    RiskFinding,
    RiskSeverity,
)
from python_deployment_builder.security_policy import (
    TextContentEncodingError,
    decode_security_text,
    is_secret_filename,
    is_textual_content,
    text_security_findings,
)


def _check(condition: bool, code: str, description: str) -> RiskFinding:
    return RiskFinding(
        code=code,
        title=code.replace("_", " ").title(),
        severity=RiskSeverity.INFO if condition else RiskSeverity.BLOCKING,
        status=FindingStatus.DETECTED,
        description=description,
    )


def manifest_artifact_wheel_path(directory: str, filename: str) -> str | None:
    """Return one canonical kit-relative artifact path, or reject an unsafe filename."""

    posix = PurePosixPath(filename)
    windows = PureWindowsPath(filename)
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or posix.name != filename
        or not filename.lower().endswith(".whl")
    ):
        return None
    return f"deployment/{directory}/{filename}"


def approved_artifacts_by_path(artifacts: list[ApprovedArtifact]) -> dict[str, ApprovedArtifact]:
    """Require one approved record per safe, Windows-distinct materialization path."""
    result: dict[str, ApprovedArtifact] = {}
    windows_paths: set[str] = set()
    for artifact in artifacts:
        relative = manifest_artifact_wheel_path("wheels", artifact.filename)
        if relative is None:
            raise PreparationError(f"Unsafe approved artifact filename: {artifact.filename}")
        key = relative.casefold()
        if key in windows_paths:
            raise PreparationError(f"Duplicate approved artifact materialization path: {relative}")
        windows_paths.add(key)
        result[relative] = artifact
    return result


def trusted_artifact_wheel_paths(manifest: DeploymentManifest) -> set[str]:
    """Return exact manifest-owned wheel paths with dedicated validation.

    A wheel hash/index proves identity only. The sole wheels exempt from
    ordinary staged-file scanning are artifacts already validated through the
    application/dependency wheel validators and named by this manifest.
    """

    paths = {
        path
        for artifact in manifest.approved_artifacts
        if (path := manifest_artifact_wheel_path("wheels", artifact.filename)) is not None
    }
    if manifest.application_artifact is not None and (
        path := manifest_artifact_wheel_path(
            "application", manifest.application_artifact.filename
        )
    ):
        paths.add(path)
    return paths


def validate_rendered_files(
    files: dict[str, bytes],
    manifest: DeploymentManifest,
    *,
    generated_paths: set[str],
    secret_values: list[str] | None = None,
) -> list[RiskFinding]:
    checks: list[RiskFinding] = []
    application_path = (
        manifest_artifact_wheel_path("application", manifest.application_artifact.filename)
        if manifest.application_artifact is not None
        else None
    )
    approved_paths = [
        manifest_artifact_wheel_path("wheels", artifact.filename)
        for artifact in manifest.approved_artifacts
    ]
    unsafe_artifacts = [
        *(
            [f"application: {manifest.application_artifact.filename}"]
            if manifest.application_artifact is not None and application_path is None
            else []
        ),
        *(
            f"approved: {artifact.filename}"
            for artifact, path in zip(manifest.approved_artifacts, approved_paths, strict=True)
            if path is None
        ),
    ]
    checks.append(
        _check(
            not unsafe_artifacts,
            "MANIFEST_ARTIFACT_FILENAMES",
            "Manifest artifact filenames are safe wheel basenames."
            if not unsafe_artifacts
            else f"Unsafe manifest artifact filenames: {unsafe_artifacts}",
        )
    )
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
    application_hash_ok = manifest.application_artifact is None or (
        application_path is not None
        and (data := files.get(application_path))
        is not None
        and hashlib.sha256(data).hexdigest() == manifest.application_artifact.sha256
    )
    checks.append(
        _check(
            application_hash_ok,
            "APPLICATION_ARTIFACT_FINGERPRINT",
            "The first-party application artifact matches its manifest SHA-256.",
        )
    )
    artifact_hashes_ok = all(
        path is not None
        and (data := files.get(path)) is not None
        and hashlib.sha256(data).hexdigest() == artifact.sha256
        for artifact, path in zip(manifest.approved_artifacts, approved_paths, strict=True)
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
    undecodable_text: list[str] = []
    unvalidated_wheels: list[str] = []
    trusted_wheels = trusted_artifact_wheel_paths(manifest)
    # Every intentionally staged file is release content. Only exact
    # manifest-owned artifacts may remain opaque because their dedicated
    # member-level validators own their security scans.
    for relative, content in files.items():
        path = PurePosixPath(relative)
        if path.suffix.lower() == ".whl":
            if relative not in trusted_wheels:
                unvalidated_wheels.append(relative)
            continue
        if is_secret_filename(path.name):
            secret_hits.append(relative)
            continue
        if not is_textual_content(path, content):
            continue
        try:
            text = decode_security_text(path, content)
        except TextContentEncodingError:
            undecodable_text.append(relative)
            continue
        if text is None:
            continue
        findings = text_security_findings(
            text, path=path, configured_secret_values=secret_values or []
        )
        if "forbidden_shell" in findings:
            forbidden_hits.append(relative)
        if "developer_path" in findings:
            developer_path_hits.append(relative)
        if "permanent_path" in findings:
            permanent_path_hits.append(relative)
        if "program_files_write" in findings:
            program_files_hits.append(relative)
        if {"obvious_secret", "configured_secret"} & findings:
            secret_hits.append(relative)
    ps1_files = [path for path in files if PurePosixPath(path).suffix.lower() == ".ps1"]
    runtime_builder_imports = [
        path
        for path in generated_paths
        if path.startswith("deployment/runtime/")
        and b"python_deployment_builder" in files.get(path, b"")
    ]
    cache_paths = [
        path
        for path in files
        if PurePosixPath(path).suffix.lower() in {".pyc", ".pyo"}
        or any(
            re.fullmatch(r"__pycache__(?:\s*\(\d+\))?", part, re.IGNORECASE)
            for part in PurePosixPath(path).parts
        )
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
                not unvalidated_wheels,
                "NO_UNVALIDATED_STAGED_WHEELS",
                "All staged wheels are exact manifest-declared artifacts with dedicated "
                "wheel validation."
                if not unvalidated_wheels
                else "Staged wheels have not passed dedicated artifact validation: "
                f"{sorted(unvalidated_wheels)}",
            ),
            _check(
                not undecodable_text,
                "TEXT_SECURITY_DECODABLE",
                "All staged textual content is valid UTF-8/UTF-8-SIG for security scanning."
                if not undecodable_text
                else "Textual content cannot be security-scanned as UTF-8: "
                f"{undecodable_text}",
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
            _check(
                not cache_paths,
                "NO_RUNTIME_CACHES",
                f"Runtime cache files staged: {cache_paths or 'none'}",
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
