"""Orchestrate preparation, rendering, collision checks, and structural validation."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from packaging.utils import canonicalize_name

from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import (
    MaterializedRepository,
    RepositoryLoadError,
    git_skip_worktree_paths,
    materialize_git_head_snapshot,
)
from python_deployment_builder.analysis.resources import resolve_package_data_members
from python_deployment_builder.generation.acquisition import (
    PreparationError,
    acquire_pinned_uv,
    sha256_file,
)
from python_deployment_builder.generation.artifacts import (
    configured_secret_values,
    validate_application_wheel,
    validate_artifact_set,
    validate_combined_wheel_installation_paths,
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


def _allow_missing_lock_for_analysis(plan, *, dry_run: bool, prepare_lock: bool) -> bool:
    """Permit a missing lock only for a non-mutating preview or authorized preparation."""

    return plan.lockfile.status == "developer_generation_required" and (
        dry_run or prepare_lock
    )


def _is_runtime_cache(relative: Path) -> bool:
    return relative.suffix.lower() in {".pyc", ".pyo"} or any(
        PYTHON_CACHE_DIRECTORY.fullmatch(part) for part in relative.parts
    )


def _git_worktree_context(
    repository_root: Path, *, required: bool
) -> tuple[Path, PurePosixPath] | None:
    """Return the enclosing worktree and selected-root prefix for Git path normalization."""

    repository_check = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if repository_check.returncode != 0 or repository_check.stdout.strip() != "true":
        return None
    worktree = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if worktree.returncode != 0 or not worktree.stdout.strip():
        if required:
            raise PreparationError(
                "Git revision provenance is known, but the enclosing worktree could not be "
                "resolved. Generation stopped rather than comparing incompatible path bases."
            )
        return None
    worktree_root = Path(worktree.stdout.strip()).resolve()
    try:
        prefix = repository_root.resolve().relative_to(worktree_root)
    except ValueError as exc:
        if required:
            raise PreparationError(
                "Git revision provenance is known, but the selected repository is not within "
                "its reported worktree. Generation stopped rather than comparing ambiguous paths."
            ) from exc
        return None
    return worktree_root, PurePosixPath(prefix.as_posix())


def _repository_relative_git_paths(
    values: list[bytes], *, repository_prefix: PurePosixPath
) -> set[str]:
    """Normalize worktree-root Git output into selected-repository-relative paths."""

    prefix_parts = repository_prefix.parts if repository_prefix != PurePosixPath(".") else ()
    normalized: set[str] = set()
    for value in values:
        if not value:
            continue
        candidate = PurePosixPath(
            value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        )
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            raise PreparationError(
                "Git returned an unsafe repository path while checking provenance."
            )
        if prefix_parts:
            if candidate.parts[: len(prefix_parts)] != prefix_parts:
                continue
            candidate = PurePosixPath(*candidate.parts[len(prefix_parts) :])
        if candidate.parts:
            normalized.add(candidate.as_posix())
    return normalized


def _git_tracked_paths(repository_root: Path, *, required: bool) -> set[str] | None:
    context = _git_worktree_context(repository_root, required=required)
    if context is None:
        return None
    worktree_root, repository_prefix = context
    pathspec = repository_prefix.as_posix() if repository_prefix != PurePosixPath(".") else "."
    result = subprocess.run(
        [
            "git",
            "-C",
            str(worktree_root),
            "ls-files",
            "--full-name",
            "-z",
            "--",
            pathspec,
        ],
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
    return _repository_relative_git_paths(
        result.stdout.split(b"\0"), repository_prefix=repository_prefix
    )


def _dirty_tracked_deployment_paths(
    repository_root: Path, provenance_guarded: set[str]
) -> list[str]:
    context = _git_worktree_context(repository_root, required=True)
    if context is None:  # Defensive: callers only invoke this for known Git revisions.
        return []
    worktree_root, repository_prefix = context
    pathspec = repository_prefix.as_posix() if repository_prefix != PurePosixPath(".") else "."
    result = subprocess.run(
        [
            "git",
            "-C",
            str(worktree_root),
            "diff",
            "--no-renames",
            "--name-only",
            "-z",
            "HEAD",
            "--",
            pathspec,
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PreparationError(
            "Git revision provenance is known, but tracked working-tree changes could not be "
            "checked. Generation stopped rather than claiming clean-revision provenance."
        )
    changed = _repository_relative_git_paths(
        result.stdout.split(b"\0"), repository_prefix=repository_prefix
    )
    if not changed:
        return []
    with tempfile.TemporaryDirectory(prefix="pdbuilder-head-inventory-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "repository.zip"
        extracted = temporary_root / "repository"
        archived = subprocess.run(
            [
                "git",
                "-C",
                str(worktree_root),
                "archive",
                "--format=zip",
                f"--output={archive}",
                (
                    "HEAD"
                    if repository_prefix == PurePosixPath(".")
                    else f"HEAD:{repository_prefix.as_posix()}"
                ),
            ],
            capture_output=True,
            check=False,
        )
        if archived.returncode != 0:
            raise PreparationError(
                "Git revision provenance is known, but the recorded source revision could not "
                "be inventoried. Generation stopped rather than claiming clean provenance."
            )
        try:
            head_symlinks = materialize_git_head_snapshot(archive, extracted)
            head_repository = MaterializedRepository(
                root=extracted,
                source=f"{repository_root}@HEAD",
                source_kind="local",
            )
            head_assessment = assess_repository(head_repository)
            head_plan = create_deployment_plan(
                head_assessment, repository_root=extracted
            )
            head_guarded = _provenance_guard_paths(extracted, head_assessment, head_plan)
        except (OSError, RepositoryLoadError, ValueError) as exc:
            raise PreparationError(
                "Git revision provenance is known, but the recorded source revision could not "
                "be inventoried. Generation stopped rather than claiming clean provenance."
            ) from exc
    changed_symlinks = (changed & head_symlinks) | {
        path for path in changed if (repository_root / Path(path)).is_symlink()
    }
    return sorted(changed & (provenance_guarded | head_guarded) | changed_symlinks)


def _authoritative_package_data_paths(repository_root: Path, assessment, plan) -> set[str]:
    """Return concrete first-party package data required by source-mode staging."""

    if plan.deployment_mode != "source":
        return set()
    return {
        member.source_path
        for member in resolve_package_data_members(repository_root, assessment.project)
    }


def _selected_deployment_paths(repository_root: Path, assessment, plan) -> set[str]:
    selected = {"pyproject.toml", "uv.lock"}
    if plan.deployment_mode == "source":
        selected.update(
            item.path.rstrip("/")
            for item in assessment.file_inventory
            if item.role in RUNTIME_ROLES and not item.path.endswith("/")
        )
        selected.update(_authoritative_package_data_paths(repository_root, assessment, plan))
    return selected


def _analysis_policy_paths(assessment) -> set[str]:
    """Return selected-root ignore policy files that influence inventory without staging.

    Inventory deliberately reads only the source root and its descendants, not
    enclosing-worktree ignore files. Those ancestor rules therefore do not become
    staging or provenance inputs for a nested PDB source target.
    """

    return {
        item.path.rstrip("/")
        for item in assessment.file_inventory
        if not item.path.endswith("/")
        and Path(item.path).name.casefold() == ".gitignore"
    }


def _analysis_metadata_paths(assessment) -> set[str]:
    """Return parsed repository inputs that influence release planning.

    Packaging metadata and lockfiles are represented directly by the project
    assessment. Python selection also records the exact files from which it
    derived constraints (including ``.python-version`` and, when used,
    documented version evidence). These inputs need Git provenance even when
    role-aware staging intentionally does not copy them into a kit.
    """

    paths: set[str] = set()
    for value in [
        *assessment.project.metadata_files,
        *assessment.project.lockfiles,
        *(evidence.file for evidence in assessment.python.evidence),
    ]:
        if not value:
            continue
        candidate = PurePosixPath(value.replace("\\", "/"))
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            continue
        paths.add(candidate.as_posix())
    return paths


def _provenance_guard_paths(repository_root: Path, assessment, plan) -> set[str]:
    return (
        _selected_deployment_paths(repository_root, assessment, plan)
        | _analysis_policy_paths(assessment)
        | _analysis_metadata_paths(assessment)
    )


def _tracked_deployment_paths(
    repository_root: Path,
    assessment,
    plan,
    *,
    created_lock: Path | None = None,
    allow_missing_lock: bool = False,
) -> set[str]:
    selected = _selected_deployment_paths(repository_root, assessment, plan)
    analysis_policy = _analysis_policy_paths(assessment)
    declared_package_data = _authoritative_package_data_paths(
        repository_root, assessment, plan
    )
    inventory = {item.path.rstrip("/"): item for item in assessment.file_inventory}
    excluded_package_data = sorted(
        path
        for path in declared_package_data
        if path in inventory
        and inventory[path].role
        in {
            RepositoryFileRole.IGNORED_OR_LOCAL,
            RepositoryFileRole.MUTABLE_STATE_CANDIDATE,
        }
    )
    if excluded_package_data:
        raise PreparationError(
            "Authoritative setuptools package-data runtime resources conflict with "
            "source staging policy and cannot be silently omitted: "
            + ", ".join(excluded_package_data)
        )
    tracked = _git_tracked_paths(
        repository_root,
        required=assessment.repository.revision is not None,
    )
    if tracked is None:
        return selected
    if assessment.repository.revision is not None and plan.deployment_mode == "source":
        untracked_package_data = sorted(declared_package_data - tracked)
        if untracked_package_data:
            details = [
                *(f"untracked: {path}" for path in untracked_package_data),
            ]
            raise PreparationError(
                "Authoritative setuptools package-data runtime resources must be tracked and "
                "stageable for Git release generation: "
                + ", ".join(details)
            )
    if assessment.repository.revision is not None:
        untracked_policy = sorted(analysis_policy - tracked)
        if untracked_policy:
            raise PreparationError(
                "Untracked .gitignore analysis inputs cannot be combined with recorded source "
                f"revision {assessment.repository.revision}: {', '.join(untracked_policy)}. "
                "Commit or remove those policy inputs before release-oriented generation."
            )
    missing_lock_is_previewed = allow_missing_lock and not (repository_root / "uv.lock").exists()
    if created_lock is not None:
        expected_lock = (repository_root / "uv.lock").resolve()
        if created_lock.resolve() != expected_lock or not created_lock.is_file():
            raise PreparationError(
                "The lockfile reported as created by --prepare-lock is not the repository "
                "uv.lock. Generation stopped rather than widening untracked-file staging."
            )
        tracked.add("uv.lock")
    if assessment.repository.revision is not None:
        selected_for_tracking = selected - ({"uv.lock"} if missing_lock_is_previewed else set())
        untracked_selected = sorted(selected_for_tracking - tracked)
        if untracked_selected:
            raise PreparationError(
                "Selected deployment inputs must be tracked for Git release generation "
                f"at recorded source revision {assessment.repository.revision}: "
                + ", ".join(untracked_selected)
                + ". Commit those inputs, or use only the current --prepare-lock-created "
                "uv.lock exception."
            )
        dirty = _dirty_tracked_deployment_paths(
            repository_root, _provenance_guard_paths(repository_root, assessment, plan)
        )
        if dirty:
            raise PreparationError(
                "Tracked deployment inputs differ from recorded source revision "
                f"{assessment.repository.revision}: {', '.join(dirty)}. Commit or restore "
                "those inputs before release-oriented generation."
            )
    selected.intersection_update(tracked)
    return selected


def _staging_files(
    repository_root: Path,
    assessment,
    plan,
    *,
    include: bool,
    allow_missing_lock: bool = False,
    created_lock: Path | None = None,
) -> dict[str, bytes]:
    """Stage inventory-approved runtime inputs, never a broad repository copy."""

    if not include:
        return {}
    selected = _tracked_deployment_paths(
        repository_root,
        assessment,
        plan,
        created_lock=created_lock,
        allow_missing_lock=allow_missing_lock,
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
    required_package_data = _authoritative_package_data_paths(repository_root, assessment, plan)
    missing_package_data = sorted(required_package_data - files.keys())
    if missing_package_data:
        raise PreparationError(
            "Authoritative setuptools package-data runtime resources could not be staged: "
            + ", ".join(missing_package_data)
        )
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
    approved,
    application_artifact: tuple[ApplicationArtifact, Path] | None,
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
    for artifact, _path in approved:
        paths.append(f"deployment/wheels/{artifact.filename}")
    if application_artifact is not None:
        paths.append(f"deployment/application/{application_artifact[0].filename}")
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


def _obsolete_owned_paths(
    output_root: Path,
    planned_paths: list[str] | set[str],
    previous: dict[str, str],
) -> tuple[list[str], list[str]]:
    obsolete: list[str] = []
    collisions: list[str] = []
    output_root = output_root.resolve()
    for relative in sorted(set(previous) - set(planned_paths)):
        path = output_root / Path(relative)
        resolved = path.resolve()
        try:
            resolved.relative_to(output_root)
        except ValueError:
            collisions.append(f"{relative} (previous generated index contains an unsafe path)")
            continue
        if path.is_symlink():
            collisions.append(f"{relative} (obsolete previously generated path is a symlink)")
        elif not path.exists():
            continue
        elif not path.is_file():
            collisions.append(
                f"{relative} (obsolete previously generated path is not a regular file)"
            )
        elif sha256_file(path) != previous[relative]:
            collisions.append(
                f"{relative} (obsolete previously generated file was modified)"
            )
        else:
            obsolete.append(relative)
    return obsolete, collisions


def _remove_obsolete_owned_files(output_root: Path, obsolete: list[str]) -> None:
    output_root = output_root.resolve()
    for relative in obsolete:
        path = output_root / Path(relative)
        path.resolve().relative_to(output_root)
        path.unlink(missing_ok=True)


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
    approved,
    application_artifact: tuple[ApplicationArtifact, Path] | None,
    staging_source_paths: list[str],
) -> GenerationPreview:
    paths = sorted(
        set(
            _planned_generated_paths(
                plan, bootstrap_mode, approved, application_artifact
            )
            + staging_source_paths
        )
    )
    if prepare_lock and "uv.lock" not in paths:
        paths.append("uv.lock")
        paths.sort()
    previous = _load_previous_index(output_root)
    create, replace, collisions = _classify_output(output_root, paths, previous)
    obsolete, obsolete_collisions = _obsolete_owned_paths(output_root, paths, previous)
    collisions.extend(obsolete_collisions)
    actions = ["Run pinned uv lock --check with the selected Python minor."]
    if obsolete:
        actions.append(
            "Remove unchanged files owned by the previous generator run that are no longer "
            "part of the deployment kit."
        )
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
    application_model = application_artifact[0] if application_artifact else None
    if plan.deployment_mode == "package" and application_model is None:
        actions.append(
            "Provide --application-wheel; package mode cannot produce a deployable kit without "
            "a validated first-party wheel."
        )
    elif application_model is not None:
        actions.append(
            "Validated first-party application wheel "
            f"{application_model.filename} (SHA-256 {application_model.sha256})."
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
            plan.deployment_mode == "package" and application_model is None
        ),
        application_artifact=application_model,
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
    try:
        secret_values = configured_secret_values(
            item.name for item in plan.configuration if item.secret
        )
    except PreparationError as exc:
        if not dry_run:
            raise
        preview = _preview(
            plan,
            output_root,
            dry_run=True,
            bootstrap_mode=bootstrap_mode,
            system_certs=system_certs,
            prepare_lock=prepare_lock,
            approved=[],
            application_artifact=None,
            staging_source_paths=[],
        )
        preview.developer_actions.insert(0, f"Stop: {exc}")
        return GenerationResult(
            output_directory=str(output_root),
            dry_run=True,
            generated=False,
            preview=preview,
        )
    entrypoint_extra_codes = {
        "ENTRYPOINT_EXTRA_NOT_SELECTED",
        "ENTRYPOINT_EXTRA_UNDECLARED",
    } & set(plan.risk_gate.blocking_codes)
    if entrypoint_extra_codes:
        code = sorted(entrypoint_extra_codes)[0]
        if dry_run:
            preview = _preview(
                plan,
                output_root,
                dry_run=True,
                bootstrap_mode=bootstrap_mode,
                system_certs=system_certs,
                prepare_lock=prepare_lock,
                approved=[],
                application_artifact=None,
                staging_source_paths=[],
            )
            preview.developer_actions.insert(
                0, f"Stop: {code} prevents entry-point dependency readiness."
            )
            return GenerationResult(
                output_directory=str(output_root),
                dry_run=True,
                generated=False,
                preview=preview,
            )
        raise PreparationError(
            "Deployment planning is blocked: " + "; ".join(plan.readiness.blockers)
        )
    # A skip-worktree index bit means the filesystem PDB assessed may omit a
    # tracked part of HEAD.  Block both deployment modes before staging, lock
    # preparation, artifact work, or output mutation rather than claiming the
    # recorded revision represents a complete release surface.
    skip_worktree_paths = git_skip_worktree_paths(repository_root)
    if skip_worktree_paths:
        sparse_code = "SPARSE_WORKTREE_UNSUPPORTED"
        if dry_run:
            preview = _preview(
                plan,
                output_root,
                dry_run=True,
                bootstrap_mode=bootstrap_mode,
                system_certs=system_certs,
                prepare_lock=prepare_lock,
                approved=[],
                application_artifact=None,
                staging_source_paths=[],
            )
            preview.developer_actions.insert(
                0,
                f"Stop: {sparse_code} prevents release generation while Git index paths "
                "are marked skip-worktree.",
            )
            return GenerationResult(
                output_directory=str(output_root),
                dry_run=True,
                generated=False,
                preview=preview,
        )
        representative = ", ".join(skip_worktree_paths[:10])
        extra_count = len(skip_worktree_paths) - 10
        suffix = "" if extra_count <= 0 else f" (and {extra_count} more)"
        raise PreparationError(
            f"Deployment planning is blocked: {sparse_code}. The Git index marks tracked "
            "paths skip-worktree, so the current filesystem may not completely represent "
            f"HEAD: {representative}{suffix}. Populate the full working tree before generation."
        )
    # A workspace root cannot be reduced to this M6.1 kit's root
    # ``pyproject.toml`` + ``uv.lock`` representation: uv still resolves
    # member metadata under --no-install-project. Report the typed blocker
    # before staging, artifact work, or an explicitly authorized lock update.
    workspace_blockers = {
        code
        for code in plan.risk_gate.blocking_codes
        if code in {"UV_WORKSPACE_UNSUPPORTED", "UV_WORKSPACE_SOURCE_UNSUPPORTED"}
    }
    if workspace_blockers:
        workspace_code = sorted(workspace_blockers)[0]
        if dry_run:
            preview = _preview(
                plan,
                output_root,
                dry_run=True,
                bootstrap_mode=bootstrap_mode,
                system_certs=system_certs,
                prepare_lock=prepare_lock,
                approved=[],
                application_artifact=None,
                staging_source_paths=[],
            )
            preview.developer_actions.insert(
                0,
                f"Stop: {workspace_code} prevents standalone release generation.",
            )
            return GenerationResult(
                output_directory=str(output_root),
                dry_run=True,
                generated=False,
                preview=preview,
            )
        raise PreparationError(
            f"Deployment planning is blocked: {workspace_code}. "
            "M6.1 standalone deployment does not preserve or install uv workspace members."
        )
    runtime_sync_blockers = {
        code
        for code in plan.risk_gate.blocking_codes
        if code == "RUNTIME_SYNC_METADATA_UNSUPPORTED"
    }
    if runtime_sync_blockers:
        runtime_sync_code = next(iter(runtime_sync_blockers))
        if dry_run:
            preview = _preview(
                plan,
                output_root,
                dry_run=True,
                bootstrap_mode=bootstrap_mode,
                system_certs=system_certs,
                prepare_lock=prepare_lock,
                approved=[],
                application_artifact=None,
                staging_source_paths=[],
            )
            preview.developer_actions.insert(
                0,
                f"Stop: {runtime_sync_code} prevents immutable dependency synchronization.",
            )
            return GenerationResult(
                output_directory=str(output_root),
                dry_run=True,
                generated=False,
                preview=preview,
            )
        raise PreparationError(
            f"Deployment planning is blocked: {runtime_sync_code}. The pinned uv 0.12.5 "
            "lock workflow does not consume backend-only setup.cfg/setup.py dependency "
            "metadata, and PDB will not execute project metadata on the end-user system."
        )
    # An escaping setuptools root is outside both the source/provenance
    # boundary and this kit's standalone staging model.  Stop before lock
    # preparation, application-wheel work, artifact work, or output writes.
    external_root_code = "EXTERNAL_PACKAGING_ROOT_UNSUPPORTED"
    if external_root_code in plan.risk_gate.blocking_codes:
        if dry_run:
            preview = _preview(
                plan,
                output_root,
                dry_run=True,
                bootstrap_mode=bootstrap_mode,
                system_certs=system_certs,
                prepare_lock=prepare_lock,
                approved=[],
                application_artifact=None,
                staging_source_paths=[],
            )
            preview.developer_actions.insert(
                0,
                f"Stop: {external_root_code} prevents standalone release generation.",
            )
            return GenerationResult(
                output_directory=str(output_root),
                dry_run=True,
                generated=False,
                preview=preview,
            )
        raise PreparationError(
            f"Deployment planning is blocked: {external_root_code}. "
            "Authoritative setuptools packaging roots must remain inside the assessed "
            "repository."
        )
    allow_missing_lock_for_analysis = _allow_missing_lock_for_analysis(
        plan, dry_run=dry_run, prepare_lock=prepare_lock
    )
    if plan.deployment_mode == "package":
        try:
            repository_root.relative_to(output_root)
        except ValueError:
            pass
        else:
            raise PreparationError(
                "Package deployment output must be external to the application source "
                "repository so the kit cannot retain application source outside the "
                "validated first-party wheel."
            )
    if plan.entry_point is None:
        raise PreparationError(
            "Deployment readiness is blocked: " + "; ".join(plan.readiness.blockers)
        )
    if (
        not dry_run
        and plan.lockfile.status == "developer_generation_required"
        and not prepare_lock
    ):
        raise PreparationError(
            "uv.lock is missing. Re-run generation with --prepare-lock for a local "
            "repository to authorize developer-side lockfile creation."
        )
    if assessment.repository.revision is not None:
        _tracked_deployment_paths(
            repository_root,
            assessment,
            plan,
            allow_missing_lock=allow_missing_lock_for_analysis,
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
        validate_application_wheel(
            application_wheel,
            assessment,
            plan,
            repository_root=repository_root,
            validate_locked_dependencies=False,
        )
        if application_wheel is not None
        else None
    )
    approved = validate_artifact_set(artifact_values, plan)
    validate_combined_wheel_installation_paths(
        [
            *(path for _artifact, path in approved),
            *([application_artifact[1]] if application_artifact is not None else []),
        ]
    )
    requirements = {
        (canonicalize_name(item.package), item.version)
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
    }
    supplied = {(item[0].distribution_name, item[0].version) for item in approved}
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
        allow_missing_lock=allow_missing_lock_for_analysis,
    )
    preview = _preview(
        plan,
        output_root,
        dry_run=dry_run,
        bootstrap_mode=bootstrap_mode,
        system_certs=system_certs,
        prepare_lock=prepare_lock,
        approved=approved,
        application_artifact=application_artifact,
        staging_source_paths=list(source_files),
    )
    source_generated_collisions = sorted(
        set(source_files)
        & set(_planned_generated_paths(plan, bootstrap_mode, approved, application_artifact))
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
    if unresolved or unavailable:
        detail = [
            *(f"approved wheel required: {name}=={version}" for name, version in unresolved),
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
    secret_values = configured_secret_values(
        item.name for item in plan.configuration if item.secret
    )
    approved = validate_artifact_set(artifact_values, plan)
    application_artifact = (
        validate_application_wheel(
            application_wheel, assessment, plan, repository_root=repository_root
        )
        if application_wheel is not None
        else None
    )
    validate_combined_wheel_installation_paths(
        [
            *(path for _artifact, path in approved),
            *([application_artifact[1]] if application_artifact is not None else []),
        ]
    )
    requirements = {
        (canonicalize_name(item.package), item.version)
        for item in (plan.lock_graph.artifact_requirements if plan.lock_graph else [])
    }
    supplied = {(item[0].distribution_name, item[0].version) for item in approved}
    unresolved = sorted(requirements - supplied)
    unavailable = [
        item.package
        for item in (plan.lock_graph.artifact_findings if plan.lock_graph else [])
        if item.status == "unavailable"
    ]
    if unresolved or unavailable:
        detail = [
            *(f"approved wheel required: {name}=={version}" for name, version in unresolved),
            *(f"no usable artifact: {item}" for item in unavailable),
        ]
        raise PreparationError("Deployment readiness remains blocked: " + "; ".join(detail))

    source_files = _staging_files(
        repository_root,
        assessment,
        plan,
        include=output_root != repository_root,
        created_lock=(lock_result.path if prepare_lock and lock_result.created else None),
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
    final_generated_paths = set(
        _planned_generated_paths(plan, bootstrap_mode, approved, application_artifact)
    )
    final_source_generated_collisions = sorted(set(source_files) & final_generated_paths)
    if final_source_generated_collisions:
        raise PreparationError(
            "Generation output contains a runtime source conflict with a generated path: "
            + ", ".join(final_source_generated_collisions)
        )
    if output_root == repository_root:
        files_for_validation = {
            "pyproject.toml": (repository_root / "pyproject.toml").read_bytes(),
            "uv.lock": (repository_root / "uv.lock").read_bytes(),
            **owned,
        }
    else:
        files_for_validation = files
    structural_checks = validate_rendered_files(
        files_for_validation,
        manifest,
        generated_paths=set(owned),
        secret_values=list(secret_values),
    )
    previous = _load_previous_index(output_root)
    _create, _replace, final_collisions = _classify_output(
        output_root, sorted(files), previous
    )
    obsolete, obsolete_collisions = _obsolete_owned_paths(
        output_root, set(files), previous
    )
    final_collisions.extend(obsolete_collisions)
    if final_collisions:
        raise PreparationError(
            "Generation output contains files not safely owned by the previous generator run: "
            + ", ".join(final_collisions)
        )
    _remove_obsolete_owned_files(output_root, obsolete)
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
