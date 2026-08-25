"""Machine- and human-readable release packaging reports."""

from __future__ import annotations

from python_deployment_builder.models import ReleaseManifest


def release_manifest_json(manifest: ReleaseManifest) -> bytes:
    return manifest.model_dump_json(indent=2).encode("utf-8") + b"\n"


def render_release_manifest_markdown(manifest: ReleaseManifest) -> str:
    lines = [
        f"# Release package: {manifest.application_display_name}",
        "",
        f"- Final packaging state: **{manifest.final_state.value}**",
        f"- Application version: `{manifest.application_version}`",
        f"- Application ID: `{manifest.application_id}`",
        f"- Platform: `{manifest.package_platform}` / `{manifest.architecture}`",
        f"- Builder: `{manifest.builder_version}`",
        f"- Deployment: `{manifest.deployment_mode}` / `{manifest.runtime_backend}`",
        f"- Deployment fingerprint: `{manifest.deployment_fingerprint}`",
        f"- Source revision: `{manifest.source_revision or 'not recorded'}`",
        "- Assessment repository fingerprint: "
        f"`{manifest.assessment_repository_fingerprint}`",
        "",
        "## Runtime policy",
        "",
        f"- Managed Python: `{manifest.python_version}`",
        f"- Pinned uv: `{manifest.uv_version}`",
        f"- Bootstrap: `{manifest.bootstrap_mode}`",
        f"- Windows system certificates: `{str(manifest.system_certs).lower()}`",
        f"- Selected extras: `{', '.join(manifest.selected_extras) or 'none'}`",
        "- End-user source builds: disabled",
        "",
        "## Locked inputs",
        "",
        f"- `pyproject.toml` SHA-256: `{manifest.pyproject_sha256}`",
        f"- `uv.lock` SHA-256: `{manifest.lockfile_sha256}`",
    ]
    if manifest.approved_artifacts:
        lines.extend(["", "### Approved artifacts", ""])
        for artifact in manifest.approved_artifacts:
            lines.append(
                f"- `{artifact.distribution_name}=={artifact.version}` - "
                f"`{artifact.filename}` - `{artifact.sha256}`"
            )
    else:
        lines.extend(["", "No approved artifact exceptions are present."])
    lines.extend(["", "## External runtimes", ""])
    if manifest.external_runtimes:
        for runtime in manifest.external_runtimes:
            lines.append(
                f"- `{runtime.name}` - feature `{runtime.feature or 'core'}`; "
                f"detection: {runtime.detection_strategy}"
            )
    else:
        lines.append("No external runtime requirement is recorded.")
    lines.extend(
        [
            "",
            "## Distribution",
            "",
            f"- ZIP: `{manifest.zip_filename}`",
            f"- ZIP bytes: `{manifest.zip_byte_size}`",
            f"- ZIP SHA-256: `{manifest.zip_sha256}`",
            f"- Source kit validation: `{manifest.static_validation_state}`",
            f"- Extracted ZIP validation: `{manifest.extracted_zip_validation_state}`",
            "",
            "Packaging does not constitute application acceptance. Complete `SMOKE-TEST.txt` "
            "on a representative Windows Standard User account before publication.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = ["release_manifest_json", "render_release_manifest_markdown"]
