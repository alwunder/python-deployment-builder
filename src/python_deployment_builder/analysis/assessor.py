"""High-level static repository assessment pipeline."""

from __future__ import annotations

import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.analysis.dependencies import (
    apparently_unused_dependencies,
    enrich_dependencies,
)
from python_deployment_builder.analysis.entrypoints import detect_entry_point_candidates
from python_deployment_builder.analysis.guidance import build_structural_guidance
from python_deployment_builder.analysis.imports import scan_imports
from python_deployment_builder.analysis.inventory import (
    apply_mutable_state_roles,
    apply_resource_roles,
    classify_ignored_mutable_state,
    inspect_deployment_support,
    inventory_repository,
    promote_imported_application_files,
)
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import (
    MaterializedRepository,
    git_skip_worktree_paths,
    repository_fingerprint,
)
from python_deployment_builder.analysis.resources import inspect_resources
from python_deployment_builder.analysis.risks import build_risks, rate_suitability
from python_deployment_builder.analysis.runtime_assumptions import scan_runtime_assumptions
from python_deployment_builder.models import (
    Evidence,
    FindingStatus,
    RepositoryAssessment,
    RepositoryFileRole,
    RepositoryIdentity,
    RiskFinding,
    RiskSeverity,
)


def _git_revision(root: Path) -> str | None:
    """Read the selected root's Git HEAD using Git's own repository semantics."""

    # ``.git`` may be a directory, an indirection file for a linked worktree,
    # or a submodule gitdir reference.  Git plumbing preserves that identity
    # while still reporting the enclosing worktree's revision for a selected
    # nested project directory.
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    valid_object_id = re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value)
    return value.lower() if result.returncode == 0 and valid_object_id else None


def assess_repository(repository: MaterializedRepository) -> RepositoryAssessment:
    """Run the complete non-executing Milestone 1 assessment."""

    root = repository.root
    metadata = inspect_metadata(root)
    inventory = inventory_repository(root, metadata.project.source_roots)
    promote_imported_application_files(
        root,
        inventory.items,
        inventory.application_files,
        metadata.project.source_roots,
    )
    imports = scan_imports(
        root,
        metadata.project.source_roots,
        metadata.dependencies,
        application_files=inventory.application_files,
    )
    dependencies = enrich_dependencies(metadata.dependencies, imports.observations)
    runtime = scan_runtime_assumptions(
        root,
        metadata.project.source_roots,
        application_files=inventory.application_files,
    )
    resources, resource_configuration = inspect_resources(
        root,
        metadata.project.source_roots,
        application_files=inventory.application_files,
        project=metadata.project,
    )
    apply_resource_roles(inventory.items, resources)
    apply_mutable_state_roles(inventory.items, resources, runtime.write_locations)
    scope = classify_ignored_mutable_state(inventory.items, resources)
    mutable_state_paths = {
        item.path
        for item in inventory.items
        if item.role == RepositoryFileRole.MUTABLE_STATE_CANDIDATE
    }
    resources = [item for item in resources if item.path not in mutable_state_paths]
    candidates = detect_entry_point_candidates(root, inventory.application_files)
    (
        deployment_support,
        vendor_runtimes,
        deployment_support_dependencies,
    ) = inspect_deployment_support(root, inventory.items)
    ignored_paths = {
        item.path.rstrip("/")
        for item in inventory.items
        if item.role == RepositoryFileRole.IGNORED_OR_LOCAL
    }
    ignored_resources = [
        resource
        for resource in resources
        if any(
            resource.path == ignored or resource.path.startswith(ignored + "/")
            for ignored in ignored_paths
        )
    ]
    ignored_imports = [
        item
        for item in inventory.items
        if item.role == RepositoryFileRole.IGNORED_OR_LOCAL
        and any(
            evidence.detail.startswith("Application source imports local module")
            for evidence in item.evidence
        )
    ]
    configuration = [*runtime.configuration_requirements, *resource_configuration]
    risks = build_risks(
        metadata.project,
        dependencies,
        imports.observations,
        runtime.runtime_requirements,
        resources,
        runtime.write_locations,
        configuration,
    )
    skip_worktree_paths = git_skip_worktree_paths(root)
    if skip_worktree_paths:
        displayed = skip_worktree_paths[:10]
        risks.append(
            RiskFinding(
                code="SPARSE_WORKTREE_UNSUPPORTED",
                title="Sparse Git working tree cannot represent a complete release source",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    f"The Git index marks {len(skip_worktree_paths)} tracked path(s) as "
                    "skip-worktree, so the current filesystem may not completely represent "
                    "the recorded HEAD revision."
                ),
                recommendation=(
                    "Populate the full repository working tree before generating a release kit."
                ),
                evidence=[
                    Evidence(
                        file=path,
                        detail="Git index marks this tracked path skip-worktree.",
                    )
                    for path in displayed
                ],
            )
        )
    if metadata.uv_workspace:
        risks.append(
            RiskFinding(
                code="UV_WORKSPACE_UNSUPPORTED",
                title="uv workspace deployment is not supported",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    "This project declares a uv workspace. M6.1 standalone deployment does "
                    "not preserve or install uv workspace members, while locked workspace "
                    "validation depends on their metadata."
                ),
                recommendation=(
                    "Generate a standalone non-workspace project or wait for workspace-aware "
                    "deployment support."
                ),
                evidence=metadata.uv_workspace_evidence,
            )
        )
    elif metadata.uv_workspace_source:
        risks.append(
            RiskFinding(
                code="UV_WORKSPACE_SOURCE_UNSUPPORTED",
                title="uv workspace source is declared without workspace support",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    "A uv source is marked workspace=true, but this project does not declare "
                    "a supported standalone workspace contract."
                ),
                recommendation=(
                    "Use a standalone dependency source or define workspace-aware deployment "
                    "in a future milestone."
                ),
                evidence=metadata.uv_workspace_evidence,
            )
        )
    if metadata.setuptools_surface_unresolved:
        risks.append(
            RiskFinding(
                code="PACKAGING_SURFACE_UNRESOLVED",
                title="Setuptools packaging surface requires static resolution",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.NEEDS_VALIDATION,
                description=(
                    "setup.py declares packaging-surface configuration that PDB cannot "
                    "statically resolve without executing target code."
                ),
                recommendation=(
                    "Use literal setuptools package configuration or retain source deployment; "
                    "package mode requires an authoritative static surface."
                ),
                evidence=metadata.setuptools_surface_evidence,
            )
        )
    if metadata.setuptools_external_packaging_roots:
        risks.append(
            RiskFinding(
                code="EXTERNAL_PACKAGING_ROOT_UNSUPPORTED",
                title="Setuptools packaging root escapes the assessed repository",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    "The project declares first-party setuptools packaging content outside "
                    "the assessed repository boundary. PDB cannot inspect, stage, or prove "
                    "that external source as part of a standalone release."
                ),
                recommendation=(
                    "Move the first-party package root into the assessed repository or use "
                    "a future workspace-aware deployment workflow."
                ),
                evidence=metadata.setuptools_external_packaging_root_evidence,
            )
        )
    unusual_scope_imports = [
        item
        for item in imports.observations
        if item.import_name.lower()
        in {"test", "tests", "doc", "docs", "example", "examples", "deployment"}
    ]
    generation_excluded_imports = [
        item
        for item in unusual_scope_imports
        if item.import_name.lower() in {"test", "tests", "deployment"}
    ]
    advisory_scope_imports = [
        item for item in unusual_scope_imports if item not in generation_excluded_imports
    ]
    if advisory_scope_imports:
        risks.append(
            RiskFinding(
                code="APPLICATION_IMPORTS_NON_RUNTIME_SCOPE",
                title="Application source imports a normally excluded repository scope",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.DETECTED,
                description=(
                    "Production source directly imports a tests/docs/examples/deployment "
                    "namespace. "
                    "That dependency is reported rather than silently excluded."
                ),
                recommendation=(
                    "Make the runtime dependency explicit or separate shared runtime code."
                ),
                evidence=[
                    evidence for item in advisory_scope_imports for evidence in item.evidence
                ],
            )
        )
    if generation_excluded_imports:
        risks.append(
            RiskFinding(
                code="APPLICATION_IMPORTS_GENERATION_EXCLUDED_SCOPE",
                title="Application source imports a generation-excluded repository scope",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    "Production source imports a tests or deployment namespace that source-mode "
                    "generation reserves or excludes."
                ),
                recommendation=(
                    "Separate runtime code from the reserved scope before generic generation."
                ),
                evidence=[
                    evidence
                    for item in generation_excluded_imports
                    for evidence in item.evidence
                ],
            )
        )
    if ignored_resources or ignored_imports:
        ignored_names = [
            *(resource.path for resource in ignored_resources),
            *(item.path for item in ignored_imports),
        ]
        risks.append(
            RiskFinding(
                code="RUNTIME_DEPENDENCY_IS_IGNORED",
                title="Runtime dependency is excluded by repository ignore rules",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.DETECTED,
                description=(
                    "Application source statically references ignored runtime paths: "
                    + ", ".join(sorted(ignored_names))
                ),
                recommendation="Track/package each runtime resource or remove the dependency.",
                evidence=[
                    *(evidence for resource in ignored_resources for evidence in resource.evidence),
                    *(evidence for item in ignored_imports for evidence in item.evidence),
                ],
            )
        )
    if deployment_support:
        risks.append(
            RiskFinding(
                code="EXISTING_DEPLOYMENT_COLLISION_POTENTIAL",
                title="Existing deployment files may overlap generated kit paths",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.NEEDS_VALIDATION,
                description=(
                    "PDB detected existing launch, repair, diagnostics, or deployment-support "
                    "paths. Generation collision checks remain authoritative."
                ),
                recommendation=(
                    "Use an external staging directory and review collisions before generation."
                ),
                evidence=[
                    evidence for item in deployment_support for evidence in item.evidence[:1]
                ],
            )
        )
    guidance = build_structural_guidance(
        metadata.project,
        candidates,
        resources,
        runtime.write_locations,
        deployment_support,
        vendor_runtimes,
        ignored_resources,
    )
    rating, summary = rate_suitability(risks)
    limitations = [
        "Static assessment did not import or execute target-project code.",
        "Package index and Windows wheel availability were not queried.",
        "Import-to-distribution matching uses declared metadata plus a conservative mapping table.",
        "Write-location and launch-critical classifications are heuristic until "
        "runtime validation.",
    ]
    for parse_error in [*imports.parse_errors, *runtime.parse_errors]:
        limitations.append(f"Python source could not be parsed: {parse_error}")
    revision = _git_revision(root)
    if revision is None and repository.source_kind == "github_archive":
        archive_revision = re.search(r"-([0-9a-f]{7,40})$", root.name, flags=re.IGNORECASE)
        revision = archive_revision.group(1) if archive_revision else None
    fingerprint_roles = {
        RepositoryFileRole.APPLICATION_SOURCE,
        RepositoryFileRole.RUNTIME_RESOURCE,
    }
    fingerprint_files = {
        root / item.path
        for item in inventory.items
        if not item.path.endswith("/") and item.role in fingerprint_roles
    }
    fingerprint_files.update(root / name for name in metadata.project.metadata_files)
    fingerprint_files.update(root / name for name in metadata.project.lockfiles)
    fingerprint_files.update(
        root / item.path for item in inventory.items if item.path.endswith(".gitignore")
    )
    return RepositoryAssessment(
        generated_at=datetime.now(UTC),
        tool_version=__version__,
        repository=RepositoryIdentity(
            source=repository.source,
            source_kind=repository.source_kind,
            root_name=root.name,
            revision=revision,
            fingerprint=repository_fingerprint(root, sorted(fingerprint_files)),
            fingerprint_scope="deployment_inputs",
        ),
        project=metadata.project,
        file_inventory=inventory.items,
        analysis_scope=scope,
        entry_point_candidates=candidates,
        deployment_support=deployment_support,
        deployment_support_dependencies=deployment_support_dependencies,
        vendor_runtimes=vendor_runtimes,
        structural_guidance=guidance,
        python=metadata.python,
        dependencies=dependencies,
        imports=imports.observations,
        declared_but_apparently_unused=apparently_unused_dependencies(
            dependencies, imports.observations
        ),
        runtime_requirements=runtime.runtime_requirements,
        resources=resources,
        write_locations=runtime.write_locations,
        configuration_requirements=configuration,
        risks=risks,
        rating=rating,
        rating_summary=summary,
        analysis_limitations=limitations,
    )
