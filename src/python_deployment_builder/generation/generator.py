"""Orchestrate preparation, rendering, collision checks, and structural validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from packaging.utils import canonicalize_name

from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import (
    PreparationError,
    acquire_pinned_uv,
    sha256_file,
)
from python_deployment_builder.generation.artifacts import (
    validate_application_wheel,
    validate_artifact_set,
)
from python_deployment_builder.generation.manifest import (
    build_deployment_manifest,
    source_roots_from_plan,
)
from python_deployment_builder.generation.preparation import prepare_lockfile
from python_deployment_builder.generation.structural import (
    validate_rendered_files,
    validate_written_files,
)
from python_deployment_builder.generation.templates import (
    load_template,
    render_template,
    safe_windows_label,
)
from python_deployment_builder.models import (
    ApplicationArtifact,
    GeneratedArtifact,
    GenerationPreview,
    GenerationResult,
    RepositoryFileRole,
)
from python_deployment_builder.planning import create_deployment_plan

GENERATED_INDEX = "deployment/generated-files.json"
PYTHON_CACHE_DIRECTORY = re.compile(r"^__pycache__(?:\s*\(\d+\))?$", re.IGNORECASE)
RUNTIME_ROLES = {
    RepositoryFileRole.APPLICATION_SOURCE,
    RepositoryFileRole.RUNTIME_RESOURCE,
}


def _is_runtime_cache(relative: Path) -> bool:
    return relative.suffix.lower() in {".pyc", ".pyo"} or any(
        PYTHON_CACHE_DIRECTORY.fullmatch(part) for part in relative.parts
    )


def _git_tracked_paths(repository_root: Path, *, required: bool) -> set[str] | None:
    repository_check = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if repository_check.returncode != 0 or repository_check.stdout.strip() != "true":
        return None
    result = subprocess.run(
        ["git", "-C", str(repository_root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        if required:
            raise PreparationError(
                "Git revision provenance is known, but tracked deployment inputs could not "
                "be enumerated. Generation stopped rather than staging local files."
            )
        return None
    return {
        value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for value in result.stdout.split(b"\0")
        if value
    }


def _dirty_tracked_deployment_paths(
    repository_root: Path, selected: set[str]
) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repository_root), "diff", "--name-only", "-z", "HEAD", "--"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PreparationError(
            "Git revision provenance is known, but tracked working-tree changes could not be "
            "checked. Generation stopped rather than claiming clean-revision provenance."
        )
    changed = {
        value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for value in result.stdout.split(b"\0")
        if value
    }
    return sorted(changed & selected)


def _staging_files(
    repository_root: Path,
    assessment,
    plan,
    *,
    include: bool,
    allow_missing_lock: bool = False,
) -> dict[str, bytes]:
    """Stage inventory-approved runtime inputs, never a broad repository copy."""

    if not include:
        return {}
    selected = {"pyproject.toml", "uv.lock"}
    if plan.deployment_mode == "source":
        selected.update(
            item.path.rstrip("/")
            for item in assessment.file_inventory
            if item.role in RUNTIME_ROLES and not item.path.endswith("/")
        )
    tracked = _git_tracked_paths(
        repository_root,
        required=assessment.repository.revision is not None,
    )
    if tracked is not None:
        selected.intersection_update(tracked)
        if assessment.repository.revision is not None:
            dirty = _dirty_tracked_deployment_paths(repository_root, selected)
            if dirty:
                raise PreparationError(
                    "Tracked deployment inputs differ from recorded source revision "
                    f"{assessment.repository.revision}: {', '.join(dirty)}. Commit or restore "
                    "those inputs before release-oriented generation."
                )
    files: dict[str, bytes] = {}
    for relative_text in sorted(selected):
        relative = Path(relative_text)
        if _is_runtime_cache(relative):
            continue
        path = repository_root / relative
        if path.is_symlink():
            raise PreparationError(f"Staging refuses repository symbolic links: {relative_text}")
        if path.is_file():
            files[relative.as_posix()] = path.read_bytes()
    required = {"pyproject.toml"} | (set() if allow_missing_lock else {"uv.lock"})
    missing = sorted(required - files.keys())
    if missing:
        raise PreparationError("Required deployment input is missing: " + ", ".join(missing))
    return files


def _root_names(display_name: str) -> tuple[str, str, str]:
    label = safe_windows_label(display_name)
    return (
        f"Run {label}.bat",
        f"Repair {label} Environment.bat",
        f"Diagnose {label}.bat",
    )


def _template_values(plan, bootstrap_mode: str, system_certs: bool) -> dict[str, str]:
    return {
        "APP_ID": plan.application_id,
        "APP_DISPLAY": safe_windows_label(plan.application_display_name),
        "UV_VERSION": plan.runtime.uv_version,
        "PYTHON_VERSION": plan.runtime.python_version,
        "BOOTSTRAP_MODE": bootstrap_mode,
        "UV_URL": plan.runtime.bootstrap_artifact.url,
        "UV_SHA256": plan.runtime.bootstrap_artifact.sha256,
        "SYSTEM_CERTS_LINE": (
            'set "UV_SYSTEM_CERTS=true"' if system_certs else 'set "UV_SYSTEM_CERTS="'
        ),
        "SYSTEM_CERTS_DESCRIPTION": "enabled" if system_certs else "disabled",
    }


def _planned_generated_paths(
    plan,
    bootstrap_mode: str,
    artifact_values: list[str],
    application_wheel: Path | None,
) -> list[str]:
    run_name, repair_name, diagnose_name = _root_names(plan.application_display_name)
    paths = [
        run_name,
        repair_name,
        diagnose_name,
        "deployment/manifest.json",
        GENERATED_INDEX,
        "deployment/bootstrap/bootstrap.cmd",
        "deployment/runtime/runtime_common.py",
        "deployment/runtime/manage.py",
        "deployment/runtime/launch.py",
        "deployment/runtime/diagnostics.py",
        "deployment/README-deployment.txt",
    ]
    if bootstrap_mode == "bundled_uv":
        paths.append("deployment/bootstrap/uv.exe")
    for value in artifact_values:
        _name, separator, raw_path = value.partition("=")
        if separator and raw_path:
            paths.append(f"deployment/wheels/{Path(raw_path).name}")
    if application_wheel is not None:
        paths.append(f"deployment/application/{application_wheel.name}")
    return sorted(set(paths))


def _load_previous_index(output_root: Path) -> dict[str, str]:
    path = output_root / Path(GENERATED_INDEX)
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("application_id") and isinstance(value.get("files"), list):
            return {
                str(item["path"]): str(item["sha256"])
                for item in value["files"]
                if isinstance(item, dict) and "path" in item and "sha256" in item
            }
    except (OSError, json.JSONDecodeError, TypeError, KeyError):
        pass
    return {}


def _classify_output(
    output_root: Path,
    planned_paths: list[str],
    previous: dict[str, str],
) -> tuple[list[str], list[str], list[str]]:
    create: list[str] = []
    replace: list[str] = []
    collisions: list[str] = []
    for relative in planned_paths:
        path = output_root / Path(relative)
        if not path.exists():
            create.append(relative)
        elif relative not in previous and relative != GENERATED_INDEX:
            collisions.append(relative)
        elif path.is_file() and relative in previous and sha256_file(path) != previous[relative]:
            collisions.append(f"{relative} (previously generated file was modified)")
        else:
            replace.append(relative)
    return create, replace, collisions


def _render_owned_files(
    plan,
    repository_root: Path,
    *,
    bootstrap_mode: str,
    system_certs: bool,
    approved,
    bundled_uv: Path | None,
    application_artifact: tuple[ApplicationArtifact, Path] | None = None,
) -> tuple[dict[str, bytes], object]:
    values = _template_values(plan, bootstrap_mode, system_certs)
    run_name, repair_name, diagnose_name = _root_names(plan.application_display_name)
    owned: dict[str, bytes] = {
        run_name: render_template("run.bat.tmpl", values),
        repair_name: render_template("repair.bat.tmpl", values),
        diagnose_name: render_template("diagnose.bat.tmpl", values),
        "deployment/bootstrap/bootstrap.cmd": render_template("bootstrap.cmd.tmpl", values),
        "deployment/runtime/runtime_common.py": load_template("runtime_common.py").encode(),
        "deployment/runtime/manage.py": load_template("manage.py").encode(),
        "deployment/runtime/launch.py": load_template("launch.py").encode(),
        "deployment/runtime/diagnostics.py": load_template("diagnostics.py").encode(),
        "deployment/README-deployment.txt": render_template(
            "README-deployment.txt.tmpl", values
        ),
    }
    if bootstrap_mode == "bundled_uv":
        if bundled_uv is None:
            raise PreparationError("bundled_uv generation requires a verified uv.exe.")
        owned["deployment/bootstrap/uv.exe"] = bundled_uv.read_bytes()
    for artifact, path in approved:
        owned[f"deployment/wheels/{artifact.filename}"] = path.read_bytes()
    if application_artifact is not None:
        artifact, path = application_artifact
        owned[f"deployment/application/{artifact.filename}"] = path.read_bytes()

    referenced = [
        *owned,
        "deployment/manifest.json",
        GENERATED_INDEX,
        "pyproject.toml",
        "uv.lock",
    ]
    manifest = build_deployment_manifest(
        plan,
        repository_root,
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        approved_artifacts=[item[0] for item in approved],
        application_artifact=application_artifact[0] if application_artifact else None,
        bundled_uv_sha256=sha256_file(bundled_uv) if bundled_uv else None,
        referenced_files=referenced,
    )
    owned["deployment/manifest.json"] = (
        manifest.model_dump_json(indent=2).encode("utf-8") + b"\n"
    )
    return owned, manifest


def _generated_index(application_id: str, owned: dict[str, bytes]) -> bytes:
    payload = {
        "schema_version": "1.0",
        "application_id": application_id,
        "files": [
            {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for path, data in sorted(owned.items())
            if path != GENERATED_INDEX
        ],
    }
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def _write_files(output_root: Path, files: dict[str, bytes]) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    for relative, data in files.items():
        destination = output_root / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".pdbuilder-writing")
        temporary.write_bytes(data)
        temporary.replace(destination)


def _preview(
    plan,
    output_root: Path,
    *,
    dry_run: bool,
    bootstrap_mode: str,
    system_certs: bool,
    prepare_lock: bool,
    artifact_values: list[str],
    application_wheel: Path | None,
    application_artifact: ApplicationArtifact | None,
    staging_source_paths: list[str],
) -> GenerationPreview:
    paths = sorted(
        set(
            _planned_generated_paths(
                plan, bootstrap_mode, artifact_values, application_wheel
            )
            + staging_source_paths
        )
    )
    if prepare_lock and "uv.lock" not in paths:
        paths.append("uv.lock")
        paths.sort()
    previous = _load_previous_index(output_root)
    create, replace, collisions = _classify_output(output_root, paths, previous)
    actions = ["Run pinned uv lock --check with the selected Python minor."]
    if plan.lockfile.status == "developer_generation_required":
        actions.insert(
            0,
            "Create uv.lock with pinned uv and the selected Python minor."
            if prepare_lock
            else "Stop until --prepare-lock explicitly authorizes uv.lock creation.",
        )
    if bootstrap_mode == "bundled_uv":
        actions.append("Download, SHA-256 verify, version-check, and bundle the pinned uv.exe.")
    for requirement in plan.lock_graph.artifact_requirements if plan.lock_graph else []:
        actions.append(
            f"Validate an approved wheel for {requirement.package}=={requirement.version}."
        )
    if plan.deployment_mode == "package" and application_artifact is None:
        actions.append(
            "Provide --application-wheel; package mode cannot produce a deployable kit without "
            "a validated first-party wheel."
        )
    elif application_artifact is not None:
        actions.append(
            "Validated first-party application wheel "
            f"{application_artifact.filename} (SHA-256 {application_artifact.sha256})."
        )
    return GenerationPreview(
        application_id=plan.application_id,
        deployment_mode=plan.deployment_mode,
        output_directory=str(output_root),
        dry_run=dry_run,
        readiness_before=plan.readiness.state,
        source_roots=(
            source_roots_from_plan(plan) if plan.deployment_mode == "source" else []
        ),
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        developer_actions=actions,
        application_wheel_required=(
            plan.deployment_mode == "package" and application_artifact is None
        ),
        application_artifact=application_artifact,
        files_to_create=create,
        files_to_replace=replace,
        collisions=collisions,
        runtime_paths=plan.runtime.paths,
        launcher_behavior=[
            "Resolve PROJECT_ROOT from the root BAT location.",
            "Use successful fingerprinted state for the fast path.",
            "Otherwise provision pinned managed Python and perform locked, no-build sync.",
            "Use pythonw.exe for GUI launch and python.exe for console/management tasks.",
        ],
    )


def generate_deployment_kit(
    repository: MaterializedRepository,
    output_root: Path,
    *,
    architecture: str = "x86_64",
    online: bool = False,
    selected_extras: list[str] | None = None,
    prepare_lock: bool = False,
    bootstrap_mode: str = "bundled_uv",
    system_certs: bool = False,
    artifact_values: list[str] | None = None,
    application_wheel: Path | None = None,
    dry_run: bool = False,
    uv_cache_root: Path | None = None,
) -> GenerationResult:
    if bootstrap_mode not in {"bundled_uv", "online_cmd"}:
        raise PreparationError(f"Unsupported bootstrap mode: {bootstrap_mode}")
    if prepare_lock and repository.source_kind != "local":
        raise PreparationError("--prepare-lock is allowed only for a local repository path.")
    selected_extras = selected_extras or []
    artifact_values = artifact_values or []
    repository_root = repository.root.resolve()
    output_root = output_root.resolve()
    if output_root != repository_root:
        try:
            output_root.relative_to(repository_root)
        except ValueError:
            pass
        else:
            raise PreparationError(
                "A staging output directory may not be nested inside the source repository. "
                "Use the repository root explicitly or choose an external staging directory."
            )

    assessment = assess_repository(repository)
    plan = create_deployment_plan(
        assessment,
        architecture=architecture,
        online=online,
        selected_extras=selected_extras,
        repository_root=repository_root,
    )
    if plan.entry_point is None:
        raise PreparationError(
            "Deployment readiness is blocked: " + "; ".join(plan.readiness.blockers)
        )
    if plan.deployment_mode_condition in {
        "DEPLOYMENT_MODE_CONFLICT",
        "INSTALLED_PROJECT_REQUIRED",
    }:
        raise PreparationError(
            "Deployment mode is structurally unsafe: " + "; ".join(plan.readiness.blockers)
        )
    if plan.deployment_mode != "package" and application_wheel is not None:
        raise PreparationError("--application-wheel is accepted only for package deployment mode.")
    application_artifact = (
        validate_application_wheel(application_wheel.resolve(), assessment, plan)
        if application_wheel is not None
        else None
    )
    approved = validate_artifact_set(artifact_values, plan)
    requirements = {
        canonicalize_name(item.package)
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
    }
    supplied = {item[0].distribution_name for item in approved}
    unresolved = sorted(requirements - supplied)
    unavailable = [
        item.package
        for item in (plan.lock_graph.artifact_findings if plan.lock_graph else [])
        if item.status == "unavailable"
    ]
    source_files = _staging_files(
        repository_root,
        assessment,
        plan,
        include=output_root != repository_root,
        allow_missing_lock=prepare_lock and plan.lockfile.status == "developer_generation_required",
    )
    preview = _preview(
        plan,
        output_root,
        dry_run=dry_run,
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        prepare_lock=prepare_lock,
        artifact_values=artifact_values,
        application_wheel=application_wheel,
        application_artifact=(application_artifact[0] if application_artifact else None),
        staging_source_paths=list(source_files),
    )
    source_generated_collisions = sorted(
        set(source_files)
        & set(_planned_generated_paths(plan, bootstrap_mode, artifact_values, application_wheel))
    )
    preview.collisions.extend(
        f"{path} (runtime source conflicts with a generated path)"
        for path in source_generated_collisions
    )
    if dry_run:
        return GenerationResult(
            output_directory=str(output_root),
            dry_run=True,
            generated=False,
            preview=preview,
        )
    if preview.collisions:
        raise PreparationError(
            "Generation output contains files not safely owned by the previous generator run: "
            + ", ".join(preview.collisions)
        )
    if plan.deployment_mode == "package" and application_artifact is None:
        raise PreparationError(
            "Package deployment mode requires --application-wheel with a developer-built "
            "first-party wheel."
        )
    if plan.risk_gate.outcome == "block":
        raise PreparationError(
            "Deployment planning is blocked: " + ", ".join(plan.risk_gate.blocking_codes)
        )
    if plan.lockfile.status == "developer_generation_required" and not prepare_lock:
        raise PreparationError(
            "uv.lock is missing. Re-run generation with --prepare-lock for a local "
            "repository to authorize developer-side lockfile creation."
        )
    if unresolved or unavailable:
        detail = [
            *(f"approved wheel required: {item}" for item in unresolved),
            *(f"no usable artifact: {item}" for item in unavailable),
        ]
        raise PreparationError("Deployment readiness remains blocked: " + "; ".join(detail))

    uv_executable = acquire_pinned_uv(
        plan.runtime.bootstrap_artifact,
        cache_root=uv_cache_root,
    )
    lock_result = prepare_lockfile(
        repository_root,
        plan,
        uv_executable,
        allow_create=prepare_lock,
        system_certs=system_certs,
    )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(
        assessment,
        architecture=architecture,
        online=online,
        selected_extras=selected_extras,
        repository_root=repository_root,
    )
    approved = validate_artifact_set(artifact_values, plan)
    application_artifact = (
        validate_application_wheel(application_wheel.resolve(), assessment, plan)
        if application_wheel is not None
        else None
    )
    requirements = {
        canonicalize_name(item.package)
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
    }
    supplied = {item[0].distribution_name for item in approved}
    unresolved = sorted(requirements - supplied)
    unavailable = [
        item.package
        for item in (plan.lock_graph.artifact_findings if plan.lock_graph else [])
        if item.status == "unavailable"
    ]
    if unresolved or unavailable:
        detail = [
            *(f"approved wheel required: {item}" for item in unresolved),
            *(f"no usable artifact: {item}" for item in unavailable),
        ]
        raise PreparationError("Deployment readiness remains blocked: " + "; ".join(detail))

    source_files = _staging_files(
        repository_root, assessment, plan, include=output_root != repository_root
    )
    bundled_uv = uv_executable if bootstrap_mode == "bundled_uv" else None
    owned, manifest = _render_owned_files(
        plan,
        repository_root,
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        approved=approved,
        application_artifact=application_artifact,
        bundled_uv=bundled_uv,
    )
    index_subjects = {**source_files, **owned}
    owned[GENERATED_INDEX] = _generated_index(plan.application_id, index_subjects)
    files = {**source_files, **owned}
    if output_root == repository_root:
        files_for_validation = {
            "pyproject.toml": (repository_root / "pyproject.toml").read_bytes(),
            "uv.lock": (repository_root / "uv.lock").read_bytes(),
            **owned,
        }
    else:
        files_for_validation = files
    secret_values = [
        value
        for name in manifest.configuration_secret_names
        if (value := os.environ.get(name))
    ]
    structural_checks = validate_rendered_files(
        files_for_validation,
        manifest,
        generated_paths=set(owned),
        secret_values=secret_values,
    )
    _write_files(output_root, files)
    validate_written_files(output_root, manifest)
    artifacts = [
        GeneratedArtifact(
            path=path,
            purpose="Generated deployment kit file",
            sha256=hashlib.sha256(data).hexdigest(),
        )
        for path, data in sorted(owned.items())
    ]
    preview.readiness_after = "VALIDATION_REQUIRED"
    if lock_result.created:
        preview.repository_files_changed.append(str(lock_result.path))
    preview.developer_actions = [
        "Completed pinned uv lock --check with the selected Python minor.",
        *(
            ["Completed pinned uv acquisition, SHA-256 verification, and bundling."]
            if bootstrap_mode == "bundled_uv"
            else []
        ),
        *(
            ["Validated and copied all required approved developer wheels."]
            if approved
            else []
        ),
        *(
            ["Validated and copied the first-party application wheel."]
            if application_artifact
            else []
        ),
    ]
    return GenerationResult(
        output_directory=str(output_root),
        dry_run=False,
        generated=True,
        manifest=manifest,
        preview=preview,
        artifacts=artifacts,
        structural_checks=structural_checks,
    )
