"""Build runtime metadata and stable deployment fingerprints from a DeploymentPlan."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.generation.acquisition import PreparationError, sha256_file
from python_deployment_builder.models import (
    ApplicationArtifact,
    ApprovedArtifact,
    DeploymentManifest,
    DeploymentPlan,
)
from python_deployment_builder.security_policy import is_valid_environment_name


def source_roots_from_plan(plan: DeploymentPlan) -> list[str]:
    raw = plan.runtime.environment_variables.get("PYTHONPATH", "")
    roots: list[str] = []
    for item in raw.split(";"):
        normalized = item.replace("/", "\\").rstrip("\\")
        if normalized == "%PROJECT_ROOT%":
            roots.append(".")
        elif normalized.startswith("%PROJECT_ROOT%\\"):
            roots.append(normalized.removeprefix("%PROJECT_ROOT%\\").replace("\\", "/"))
    return roots


def _deployment_fingerprint(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_deployment_manifest(
    plan: DeploymentPlan,
    repository_root: Path,
    *,
    bootstrap_mode: str,
    system_certs: bool,
    approved_artifacts: list[ApprovedArtifact],
    bundled_uv_sha256: str | None,
    referenced_files: list[str],
    application_artifact: ApplicationArtifact | None = None,
    generated_at: datetime | None = None,
) -> DeploymentManifest:
    repository_root = repository_root.resolve()
    pyproject = repository_root / "pyproject.toml"
    lockfile = repository_root / "uv.lock"
    if not pyproject.is_file():
        raise PreparationError("Generation currently requires pyproject.toml.")
    if not lockfile.is_file():
        raise PreparationError("Generation requires a prepared, current uv.lock.")
    source_roots = source_roots_from_plan(plan) if plan.deployment_mode == "source" else []
    if plan.deployment_mode == "source" and not source_roots:
        raise PreparationError("Source deployment plan does not provide a runtime source root.")

    sync_arguments = list(plan.runtime.sync_command.arguments)
    for artifact in approved_artifacts:
        sync_arguments.extend(["--no-install-package", artifact.distribution_name])
    timestamp = generated_at or datetime.now(UTC)
    fingerprint_payload: dict[str, object] = {
        "schema_version": plan.schema_version,
        "application_id": plan.application_id,
        "deployment_mode": plan.deployment_mode,
        "python_version": plan.runtime.python_version,
        "uv_version": plan.runtime.uv_version,
        "uv_archive_sha256": plan.runtime.bootstrap_artifact.sha256,
        "bootstrap_mode": bootstrap_mode,
        "system_certs": system_certs,
        "selected_extras_fingerprint": plan.selected_extras_fingerprint,
        "sync_arguments": sync_arguments,
        "source_roots": source_roots,
        "entry_point": {
            "kind": plan.entry_point.kind,
            "module": plan.entry_point.module,
            "callable": plan.entry_point.callable,
        },
        "project_write_probe_required": plan.writes.requires_project_write_probe,
        "external_runtimes": [item.model_dump(mode="json") for item in plan.external_runtimes],
        "pyproject_sha256": sha256_file(pyproject),
        "lockfile_sha256": sha256_file(lockfile),
        "approved_artifacts": [
            {
                "name": item.distribution_name,
                "version": item.version,
                "sha256": item.sha256,
            }
            for item in approved_artifacts
        ],
        "environment_path": plan.runtime.paths.environment_path,
    }
    if application_artifact is not None:
        fingerprint_payload["application_artifact"] = {
            "name": application_artifact.distribution_name,
            "version": application_artifact.version,
            "sha256": application_artifact.sha256,
            "entry_point": application_artifact.entry_point_target,
        }
    deployment_fingerprint = _deployment_fingerprint(fingerprint_payload)
    return DeploymentManifest(
        builder_version=__version__,
        generated_at=timestamp,
        generation_id=f"{timestamp:%Y%m%dT%H%M%SZ}-{deployment_fingerprint[:12]}",
        application_id=plan.application_id,
        application_display_name=plan.application_display_name,
        deployment_mode=plan.deployment_mode,
        entry_point_name=plan.entry_point.name,
        entry_point_kind=plan.entry_point.kind,
        entry_point_module=plan.entry_point.module,
        entry_point_callable=plan.entry_point.callable,
        python_version=plan.runtime.python_version,
        architecture=plan.runtime.architecture,
        uv_version=plan.runtime.uv_version,
        uv_archive_url=plan.runtime.bootstrap_artifact.url,
        uv_archive_sha256=plan.runtime.bootstrap_artifact.sha256,
        bundled_uv_sha256=bundled_uv_sha256,
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        selected_extras=plan.runtime.selected_extras,
        selected_extras_fingerprint=plan.selected_extras_fingerprint,
        source_roots=source_roots,
        pyproject_sha256=str(fingerprint_payload["pyproject_sha256"]),
        lockfile_sha256=str(fingerprint_payload["lockfile_sha256"]),
        assessment_repository_fingerprint=plan.assessment_repository_fingerprint,
        deployment_fingerprint=deployment_fingerprint,
        approved_artifacts=approved_artifacts,
        application_artifact=application_artifact,
        external_runtimes=plan.external_runtimes,
        runtime_paths=plan.runtime.paths,
        runtime_environment=(
            plan.runtime.environment_variables
            if plan.deployment_mode == "source"
            else {
                key: value
                for key, value in plan.runtime.environment_variables.items()
                if key != "PYTHONPATH"
            }
        ),
        sync_arguments=sync_arguments,
        project_write_probe_required=plan.writes.requires_project_write_probe,
        configuration_presence_names=sorted(
            item.name for item in plan.configuration if is_valid_environment_name(item.name)
        ),
        configuration_secret_names=sorted(
            item.name
            for item in plan.configuration
            if item.secret and is_valid_environment_name(item.name)
        ),
        referenced_files=sorted(referenced_files),
        application_version=plan.application_version,
        runtime_backend=plan.runtime.backend,
        source_revision=plan.repository_revision,
    )
