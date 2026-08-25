"""Validate, archive, revalidate, and report a release-ready deployment kit."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from python_deployment_builder.models import (
    DeploymentManifest,
    PackagePreview,
    PackageResult,
    ReleaseManifest,
    ReleasePackageState,
    ValidationFinalState,
)
from python_deployment_builder.packaging.archive import (
    ArchiveSafetyError,
    collect_kit_files,
    safe_extract_zip,
    write_deterministic_zip,
)
from python_deployment_builder.packaging.reports import (
    release_manifest_json,
    render_release_manifest_markdown,
)
from python_deployment_builder.packaging.smoke import render_smoke_test
from python_deployment_builder.validation import validate_static_kit

WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class PackageError(ValueError):
    """A deployment kit cannot be safely turned into a release package."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _load_manifest(kit_root: Path) -> DeploymentManifest:
    path = kit_root / "deployment" / "manifest.json"
    try:
        return DeploymentManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        raise PackageError(f"Deployment manifest is invalid: {exc}") from exc


def _resolved_version(manifest: DeploymentManifest, requested: str | None) -> str:
    recorded = manifest.application_version
    if recorded and requested:
        try:
            if Version(recorded) != Version(requested):
                raise PackageError(
                    f"--version {requested!r} conflicts with manifest version {recorded!r}."
                )
        except InvalidVersion as exc:
            raise PackageError(f"Application version is invalid: {exc}") from exc
    value = requested or recorded
    if not value:
        raise PackageError(
            "The deployment manifest does not contain a trustworthy application version; "
            "supply --version explicitly."
        )
    try:
        return str(Version(value))
    except InvalidVersion as exc:
        raise PackageError(f"Application version is invalid: {exc}") from exc


def safe_application_slug(display_name: str, application_id: str) -> str:
    """Create a compact Windows-safe release filename component."""

    normalized = unicodedata.normalize("NFKD", display_name).encode("ascii", "ignore").decode()
    words = re.findall(r"[A-Za-z0-9]+", normalized)
    if not words:
        words = re.findall(r"[A-Za-z0-9]+", application_id)
    slug = "".join(word[:1].upper() + word[1:] for word in words) or "Application"
    if slug.upper() in WINDOWS_RESERVED:
        slug = f"Application{slug}"
    return slug[:100]


def _ensure_output_outside_kit(kit_root: Path, output_directory: Path) -> None:
    try:
        output_directory.relative_to(kit_root)
    except ValueError:
        return
    raise PackageError("Package output directory must be outside the deployment kit.")


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".pdbuilder-writing")
    temporary.write_bytes(data)
    temporary.replace(path)


def package_deployment_kit(
    kit_root: Path,
    *,
    output_directory: Path | None = None,
    version: str | None = None,
    dry_run: bool = False,
) -> PackageResult:
    """Create deterministic release artifacts only from a statically valid kit."""

    kit_root = kit_root.resolve()
    output_directory = (
        output_directory.resolve()
        if output_directory is not None
        else kit_root.parent / "distribution"
    )
    _ensure_output_outside_kit(kit_root, output_directory)
    manifest = _load_manifest(kit_root)
    validation = validate_static_kit(kit_root, dry_run=dry_run)
    if validation.final_state != ValidationFinalState.STATIC_VALID:
        failures = [
            item.code for item in validation.static_checks if item.status.value == "FAIL"
        ]
        raise PackageError(
            "Kit validation must be STATIC_VALID before packaging; failed checks: "
            + ", ".join(failures)
        )
    application_version = _resolved_version(manifest, version)
    slug = safe_application_slug(manifest.application_display_name, manifest.application_id)
    zip_filename = f"{slug}-Windows-v{application_version}.zip"
    checksum_filename = f"{zip_filename}.sha256.txt"
    files = collect_kit_files(kit_root)
    preview = PackagePreview(
        kit_root=str(kit_root),
        output_directory=str(output_directory),
        application_id=manifest.application_id,
        application_display_name=manifest.application_display_name,
        application_version=application_version,
        application_slug=slug,
        zip_filename=zip_filename,
        checksum_filename=checksum_filename,
        files_to_package=[item[0] for item in files],
        release_manifest_fields=sorted(ReleaseManifest.model_fields),
        static_validation_state=validation.final_state.value,
        dry_run=dry_run,
    )
    if dry_run:
        return PackageResult(
            generated=False,
            dry_run=True,
            state=ReleasePackageState.READY_FOR_MANUAL_ACCEPTANCE,
            preview=preview,
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    zip_path = output_directory / zip_filename
    temporary_zip = output_directory / f".{zip_filename}.pdbuilder-writing"
    if temporary_zip.exists():
        temporary_zip.unlink()
    try:
        write_deterministic_zip(kit_root, temporary_zip)
        with tempfile.TemporaryDirectory(
            prefix=f"{manifest.application_id}-package-check-",
            dir=output_directory.parent,
        ) as temporary_directory:
            extracted_root = Path(temporary_directory) / "extracted"
            safe_extract_zip(temporary_zip, extracted_root)
            extracted_validation = validate_static_kit(extracted_root)
            if extracted_validation.final_state != ValidationFinalState.STATIC_VALID:
                failures = [
                    item.code
                    for item in extracted_validation.static_checks
                    if item.status.value == "FAIL"
                ]
                raise PackageError(
                    "Extracted ZIP validation must be STATIC_VALID; failed checks: "
                    + ", ".join(failures)
                )
        zip_size = temporary_zip.stat().st_size
        zip_sha256 = _sha256(temporary_zip)
        temporary_zip.replace(zip_path)
    except (ArchiveSafetyError, OSError) as exc:
        raise PackageError(f"Release ZIP creation or verification failed: {exc}") from exc
    finally:
        if temporary_zip.exists():
            temporary_zip.unlink()

    release_manifest = ReleaseManifest(
        generated_at=datetime.now(UTC),
        application_id=manifest.application_id,
        application_display_name=manifest.application_display_name,
        application_version=application_version,
        architecture=manifest.architecture,
        builder_version=manifest.builder_version,
        deployment_fingerprint=manifest.deployment_fingerprint,
        deployment_mode=manifest.deployment_mode,
        runtime_backend=manifest.runtime_backend,
        python_version=manifest.python_version,
        uv_version=manifest.uv_version,
        bootstrap_mode=manifest.bootstrap_mode,
        system_certs=manifest.system_certs,
        selected_extras=manifest.selected_extras,
        pyproject_sha256=manifest.pyproject_sha256,
        lockfile_sha256=manifest.lockfile_sha256,
        approved_artifacts=manifest.approved_artifacts,
        external_runtimes=manifest.external_runtimes,
        source_revision=manifest.source_revision,
        assessment_repository_fingerprint=manifest.assessment_repository_fingerprint,
        zip_filename=zip_filename,
        zip_byte_size=zip_size,
        zip_sha256=zip_sha256,
    )
    checksum_path = output_directory / checksum_filename
    manifest_json_path = output_directory / "release-manifest.json"
    manifest_markdown_path = output_directory / "release-manifest.md"
    smoke_test_path = output_directory / "SMOKE-TEST.txt"
    _atomic_write(checksum_path, f"{zip_sha256}  {zip_filename}\n".encode("ascii"))
    _atomic_write(manifest_json_path, release_manifest_json(release_manifest))
    _atomic_write(
        manifest_markdown_path,
        (render_release_manifest_markdown(release_manifest) + "\n").encode("utf-8"),
    )
    _atomic_write(
        smoke_test_path,
        (render_smoke_test(manifest, zip_filename) + "\n").encode("utf-8"),
    )
    return PackageResult(
        generated=True,
        dry_run=False,
        state=ReleasePackageState.READY_FOR_MANUAL_ACCEPTANCE,
        preview=preview,
        manifest=release_manifest,
        zip_path=str(zip_path),
        checksum_path=str(checksum_path),
        manifest_json_path=str(manifest_json_path),
        manifest_markdown_path=str(manifest_markdown_path),
        smoke_test_path=str(smoke_test_path),
    )


__all__ = ["PackageError", "package_deployment_kit", "safe_application_slug"]
