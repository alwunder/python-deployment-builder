"""Convert repository facts into an explicit deployment policy."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from packaging.specifiers import InvalidSpecifier
from packaging.utils import canonicalize_name

from python_deployment_builder import __version__
from python_deployment_builder.analysis.inventory import resource_covers_inventory_path
from python_deployment_builder.analysis.resources import (
    package_surface_resolved,
    resolve_packaged_python_sources,
)
from python_deployment_builder.backends.uv_managed import UvManagedBackend
from python_deployment_builder.models import (
    ConfigurationPlan,
    DependencyAssessment,
    DeploymentPlan,
    DeploymentReadiness,
    EntrypointPlan,
    LockfilePlan,
    OnlineCompatibilityAssessment,
    PlannedCommand,
    PlanningDecision,
    PythonCandidatePlan,
    RepositoryAssessment,
    RepositoryFileRole,
    RiskGate,
    RiskSeverity,
    SuitabilityRating,
    WritePolicyPlan,
)
from python_deployment_builder.planning.bootstrap import (
    windows_bootstrap_plan,
    windows_shell_policy,
)
from python_deployment_builder.planning.external_runtimes import external_runtime_requirements
from python_deployment_builder.planning.extras import (
    build_extra_plans,
    selected_dependencies,
    validate_selected_extras,
)
from python_deployment_builder.planning.index import inspect_dependency_wheels
from python_deployment_builder.planning.lockfile import inspect_uv_lock
from python_deployment_builder.planning.platforms import windows_finding_treatments
from python_deployment_builder.planning.policies import (
    MinorPythonCompatibility,
    candidate_python_versions,
    minor_python_compatibility,
    safe_application_id,
)


def _source_entrypoint_compatible(
    assessment: RepositoryAssessment, entry_point: EntrypointPlan | None
) -> tuple[bool, list[str]]:
    if entry_point is None:
        return False, []
    module_path = Path(*entry_point.module.split("."))
    candidates: list[str] = []
    for root in assessment.project.source_roots or ["."]:
        base = Path() if root == "." else Path(root)
        candidates.extend(
            [
                (base / module_path.with_suffix(".py")).as_posix(),
                (base / module_path / "__init__.py").as_posix(),
            ]
        )
    application_paths = {
        item.path
        for item in assessment.file_inventory
        if item.role == RepositoryFileRole.APPLICATION_SOURCE
    }
    return any(path in application_paths for path in candidates), candidates


def _deployment_mode(
    assessment: RepositoryAssessment,
    entry_point: EntrypointPlan | None,
    repository_root: Path | None,
) -> tuple[str, str, str, list[str]]:
    runtime_resource_paths = {
        item.path
        for item in assessment.file_inventory
        if item.role == RepositoryFileRole.RUNTIME_RESOURCE
    }
    # Work from the same concrete promoted inventory members used by staging.
    # A conventional directory requirement (for example ``assets``) covers its
    # descendants and therefore cannot be represented by package mode unless it
    # is authoritative wheel-backed package data.
    adjacent = sorted(
        {
            item_path
            for resource in assessment.resources
            if resource.packaging_status == "repository_adjacent"
            and resource.kind != "documentation"
            for item_path in runtime_resource_paths
            if resource_covers_inventory_path(resource.path, item_path)
        }
    )
    project_writes = [
        item.path_expression
        for item in assessment.write_locations
        if item.classification == "project_local"
    ]
    analysis_root = repository_root
    if analysis_root is None and assessment.repository.source_kind == "local":
        candidate = Path(assessment.repository.source).expanduser()
        analysis_root = candidate if candidate.is_dir() else None
    wheel_backed_python = {
        member.source_path
        for member in resolve_packaged_python_sources(analysis_root, assessment.project)
    } if analysis_root is not None else set()
    source_only_python = sorted(
        item.path
        for item in assessment.file_inventory
        if item.role == RepositoryFileRole.APPLICATION_SOURCE
        and item.path not in wheel_backed_python
        # The inventory includes conventional top-level launch scripts.  They
        # are not necessarily part of the authoritative installed surface
        # (SimpleGeorefGUI retains one for direct developer use).  Constrain
        # package mode only when static import analysis proves the Python file
        # is required by production source.
        and any(
            evidence.detail.startswith("Application source imports local module")
            for evidence in item.evidence
        )
    )
    source_compatible, candidates = _source_entrypoint_compatible(assessment, entry_point)
    source_constraints = [
        *(f"repository-adjacent resource: {item}" for item in adjacent),
        *(f"source-only Python module: {item}" for item in source_only_python),
        *(f"project-local write: {item}" for item in project_writes),
    ]
    installable = bool(
        assessment.project.distribution_name
        and assessment.project.version
        and assessment.project.build_backend
    )
    surface_resolved = package_surface_resolved(assessment.project, analysis_root) and not any(
        item.code == "PACKAGING_SURFACE_UNRESOLVED" for item in assessment.risks
    )
    backend = assessment.project.build_backend or "no build backend"

    def unresolved_surface_result() -> tuple[str, str, str, list[str]]:
        return (
            "package",
            "The authoritative entry point requires installation, but M6.1 does not model "
            f"the first-party Python packaging surface for {backend}.",
            "INSTALLED_PROJECT_REQUIRED",
            [
                "PACKAGING_SURFACE_UNRESOLVED: package mode requires an authoritative "
                f"Python packaging-surface model, but {backend} is not modeled by M6.1."
            ],
        )
    if source_constraints and source_compatible:
        return (
            "source",
            "Source-only runtime requirements make an extracted-source layout necessary, and the "
            "authoritative entry point is importable from the planned source roots.",
            "SOURCE_COMPATIBLE",
            [],
        )
    if source_constraints:
        if not installable:
            return (
                "package",
                "The authoritative entry point requires installation, but buildable project "
                "metadata is incomplete.",
                "INSTALLED_PROJECT_REQUIRED",
                ["INSTALLED_PROJECT_REQUIRED: buildable project metadata is incomplete"],
            )
        if not surface_resolved:
            return unresolved_surface_result()
        return (
            "package",
            "Source layout requirements conflict with an authoritative entry point that cannot "
            "be imported from the planned source roots.",
            "DEPLOYMENT_MODE_CONFLICT",
            [
                "DEPLOYMENT_MODE_CONFLICT: "
                + "; ".join([*source_constraints, f"source candidates: {', '.join(candidates)}"])
            ],
        )
    if not source_compatible:
        if not installable:
            return (
                "package",
                "The authoritative entry point requires installation, but buildable project "
                "metadata is incomplete.",
                "INSTALLED_PROJECT_REQUIRED",
                ["INSTALLED_PROJECT_REQUIRED: buildable project metadata is incomplete"],
            )
        if not surface_resolved:
            return unresolved_surface_result()
        return (
            "package",
            "The authoritative entry point is not source-import compatible; install a validated "
            "developer-supplied first-party wheel.",
            "ENTRYPOINT_REQUIRES_PACKAGE_MODE",
            [],
        )
    if assessment.project.source_roots == ["."]:
        return (
            "source",
            "The authoritative entry point is directly importable from the flat repository "
            "source root; preserve the extracted-source contract.",
            "SOURCE_COMPATIBLE",
            [],
        )
    if not surface_resolved:
        return (
            "source",
            "The project uses "
            f"{backend}, whose installed Python packaging surface is not modeled by M6.1. "
            "The authoritative entry point is source-import compatible, so source deployment "
            "preserves the statically understood runtime surface.",
            "SOURCE_COMPATIBLE",
            [],
        )
    return (
        "package",
        "The project has an install-oriented source layout without a source-only runtime "
        "constraint; use a validated first-party wheel.",
        "PACKAGE_PREFERRED",
        [],
    )


def _entrypoint(assessment: RepositoryAssessment) -> EntrypointPlan | None:
    entries = assessment.project.entry_points
    if not entries:
        return None
    chosen = next((item for item in entries if item.kind == "gui"), entries[0])
    if ":" not in chosen.target:
        raise ValueError(f"Entry point target is not module:callable: {chosen.target}")
    module, callable_name = chosen.target.split(":", 1)
    return EntrypointPlan(
        name=chosen.name,
        target=chosen.target,
        kind=chosen.kind,
        declared_group=chosen.declared_group,
        module=module,
        callable=callable_name,
        alternatives=[item.name for item in entries if item.name != chosen.name],
    )


def _risk_gate(assessment: RepositoryAssessment) -> RiskGate:
    blocking = [item.code for item in assessment.risks if item.severity == RiskSeverity.BLOCKING]
    warnings = [item.code for item in assessment.risks if item.severity == RiskSeverity.WARNING]
    if assessment.rating == SuitabilityRating.RED and not blocking:
        blocking.append("ASSESSMENT_RED")
    if blocking:
        return RiskGate(
            outcome="block",
            blocking_codes=blocking,
            warning_codes=warnings,
            rationale="Blocking assessment findings prevent generic automatic deployment.",
        )
    if warnings:
        return RiskGate(
            outcome="allow_with_warnings",
            warning_codes=warnings,
            rationale="Planning may continue while generation remains subject to readiness gates.",
        )
    return RiskGate(
        outcome="allow",
        rationale="No blocking or warning-level assessment risks remain.",
    )


def _python_candidates(
    assessment: RepositoryAssessment,
    online: OnlineCompatibilityAssessment | None,
) -> tuple[str, list[PythonCandidatePlan]]:
    candidates: list[PythonCandidatePlan] = []
    for version in candidate_python_versions(assessment):
        try:
            precision = minor_python_compatibility(
                version, assessment.python.requires_python
            )
        except (InvalidSpecifier, ValueError):
            precision = MinorPythonCompatibility.INCOMPATIBLE
        satisfies = precision == MinorPythonCompatibility.COMPATIBLE
        compatibility = "viable" if satisfies else "incompatible"
        rationale = {
            MinorPythonCompatibility.COMPATIBLE: "Satisfies declared Python metadata.",
            MinorPythonCompatibility.INCOMPATIBLE: (
                "Does not satisfy the declared requires-python constraint."
            ),
            MinorPythonCompatibility.UNPROVABLE: (
                "Cannot prove patch-sensitive requires-python metadata for a minor-only "
                "managed runtime."
            ),
        }[precision]
        if precision == MinorPythonCompatibility.UNPROVABLE:
            compatibility = "unverified"
        if satisfies and online:
            checked = [
                item
                for item in online.dependencies
                if item.python_version == version and item.deployment_selection == "selected"
            ]
            informational = [
                item
                for item in online.dependencies
                if item.python_version == version
                and item.deployment_selection == "informational_legacy_group"
            ]
            missing = sorted(
                item.distribution_name for item in checked if item.wheel_available is False
            )
            if informational and not checked and not online.errors:
                compatibility = "unverified"
                rationale += (
                    " Legacy requirements-file wheel evidence was inspected informationally; "
                    "no deployment dependency set is authoritative."
                )
            elif online.errors or not checked:
                compatibility = "unverified"
                rationale += " Online wheel evidence is incomplete."
            elif missing:
                compatibility = "unverified"
                rationale += (
                    " Direct package wheel gaps require locked-graph/developer-artifact review: "
                    + ", ".join(missing)
                    + "."
                )
            else:
                rationale += " All selected direct dependencies publish compatible wheels."
        elif satisfies:
            compatibility = "unverified"
            rationale += " Windows wheel availability was not queried."
        candidates.append(
            PythonCandidatePlan(
                version=version,
                satisfies_requires_python=satisfies,
                compatibility=compatibility,
                rationale=rationale,
            )
        )
    viable = [item for item in candidates if item.compatibility == "viable"]
    fallback = [
        item
        for item in candidates
        if item.satisfies_requires_python and item.compatibility == "unverified"
    ]
    if not viable and not fallback:
        raise ValueError("No Python policy candidate satisfies project compatibility evidence.")
    selected = (viable or fallback)[0]
    selected.selected = True
    selected.rationale += " Selected by the policy preference order."
    return selected.version, candidates


def _lockfile_plan(lock_present: bool, runtime, python_version: str) -> LockfilePlan:
    commands: list[PlannedCommand] = []
    if not lock_present:
        commands.append(
            PlannedCommand(
                executable=runtime.paths.uv_executable,
                arguments=["lock", "--python", python_version],
                working_directory="%PROJECT_ROOT%",
                purpose="Generate the application lockfile during developer-side preparation.",
            )
        )
    commands.append(
        PlannedCommand(
            executable=runtime.paths.uv_executable,
            arguments=["lock", "--check"],
            working_directory="%PROJECT_ROOT%",
            purpose="Prove the committed lockfile is current before deployment generation.",
        )
    )
    return LockfilePlan(
        status="present_unverified" if lock_present else "developer_generation_required",
        developer_commands=commands,
    )


def _readiness(
    assessment_gate: RiskGate,
    lockfile: LockfilePlan,
    lock_graph,
    entry_point: EntrypointPlan | None,
    deployment_mode: str,
    mode_blockers: list[str],
) -> DeploymentReadiness:
    blockers: list[str] = []
    blocker_codes: list[str] = []
    pending: list[str] = []
    resolved = ["Python runtime selected", "Source/package mode selected"]
    if assessment_gate.outcome == "block":
        blockers.extend(assessment_gate.blocking_codes)
        blocker_codes.extend(assessment_gate.blocking_codes)
    if entry_point is None:
        blocker_codes.append("ENTRYPOINT_DECLARATION_REQUIRED")
        blockers.append(
            "ENTRYPOINT_DECLARATION_REQUIRED: declare an authoritative standardized entry point"
        )
    if mode_blockers:
        blocker_codes.extend(item.split(":", 1)[0] for item in mode_blockers)
        blockers.extend(mode_blockers)
    if deployment_mode == "package" and not mode_blockers:
        blocker_codes.append("APPLICATION_WHEEL_REQUIRED")
        blockers.append(
            "APPLICATION_WHEEL_REQUIRED: package mode requires a validated developer-supplied "
            "first-party wheel at generation time"
        )
    if lockfile.status == "developer_generation_required":
        blocker_codes.append("LOCKFILE_GENERATION_REQUIRED")
        blockers.append("LOCKFILE_GENERATION_REQUIRED")
    else:
        pending.append("LOCKFILE_CURRENTNESS_UNVERIFIED")
    if lock_graph and lock_graph.artifact_findings:
        blocker_codes.extend(item.code for item in lock_graph.artifact_findings)
        blockers.extend(
            (
                f"{item.code}: {item.description}"
                if item.code == "MULTI_VERSION_ARTIFACT_FORK_UNSUPPORTED"
                else f"DEVELOPER_ARTIFACT_REQUIRED:{item.package}=={item.version}"
            )
            for item in lock_graph.artifact_findings
        )
    if assessment_gate.outcome == "block":
        state = "BLOCKED"
    elif entry_point is None:
        state = "BLOCKED_PENDING_ENTRYPOINT"
    elif mode_blockers:
        state = "BLOCKED"
    elif lock_graph and lock_graph.artifact_findings:
        state = "BLOCKED_PENDING_DEVELOPER_ARTIFACT"
    elif deployment_mode == "package":
        state = "BLOCKED_PENDING_APPLICATION_WHEEL"
    elif lockfile.status == "developer_generation_required":
        state = "BLOCKED_PENDING_LOCKFILE"
    elif pending:
        state = "BLOCKED_PENDING_LOCK_VERIFICATION"
    else:
        state = "VALIDATION_REQUIRED"
    return DeploymentReadiness(
        state=state,
        blocker_codes=list(dict.fromkeys(blocker_codes)),
        blockers=blockers,
        resolved=resolved,
        pending=pending,
    )


def create_deployment_plan(
    assessment: RepositoryAssessment,
    *,
    architecture: str = "x86_64",
    online: bool = False,
    selected_extras: list[str] | None = None,
    repository_root: Path | None = None,
) -> DeploymentPlan:
    """Plan only: no target code, builds, lock updates, or environment mutations occur."""

    selected_extras = validate_selected_extras(assessment, selected_extras or [])
    selected_extra_names = {canonicalize_name(name) for name in selected_extras}
    has_authoritative_entrypoint = bool(assessment.project.entry_points)
    selected_inspection_dependencies = [
        item
        for item in assessment.dependencies
        if item.group == "runtime"
        or canonicalize_name(item.group) in selected_extra_names
    ]
    informational_inspection_dependencies: list[DependencyAssessment] = []
    if not has_authoritative_entrypoint:
        legacy_group_names = {item.name for item in assessment.project.legacy_dependency_groups}
        informational_inspection_dependencies.extend(
            item for item in assessment.dependencies if item.group in legacy_group_names
        )
        informational_inspection_dependencies.extend(assessment.deployment_support_dependencies)
    selected_distribution_names = {
        canonicalize_name(item.distribution_name) for item in selected_inspection_dependencies
    }
    deduplicated: dict[str, DependencyAssessment] = {}
    for dependency in [
        *selected_inspection_dependencies,
        *informational_inspection_dependencies,
    ]:
        deduplicated.setdefault(canonicalize_name(dependency.distribution_name), dependency)
    inspection_dependencies = list(deduplicated.values())
    versions = candidate_python_versions(assessment)
    compatibility = (
        inspect_dependency_wheels(inspection_dependencies, versions, architecture)
        if online
        else None
    )
    if compatibility:
        for item in compatibility.dependencies:
            if canonicalize_name(item.distribution_name) not in selected_distribution_names:
                item.deployment_selection = "informational_legacy_group"
    python_version, python_candidates = _python_candidates(assessment, compatibility)
    name = assessment.project.distribution_name or assessment.repository.root_name
    app_id = safe_application_id(name)
    entry_point = _entrypoint(assessment)
    mode, mode_rationale, mode_condition, mode_blockers = _deployment_mode(
        assessment, entry_point, repository_root
    )
    runtime = UvManagedBackend().build_plan(
        app_id,
        python_version,
        architecture,
        deployment_mode=mode,
        source_roots=assessment.project.source_roots,
        selected_extras=selected_extras,
    )
    lock_present = "uv.lock" in assessment.project.lockfiles
    lockfile = _lockfile_plan(lock_present, runtime, python_version)
    lock_graph = (
        inspect_uv_lock(
            repository_root,
            name,
            python_version,
            architecture,
            selected_extras,
        )
        if repository_root is not None
        else None
    )
    applicable_dependencies = selected_dependencies(
        assessment, selected_extras, python_version, architecture
    )
    extras = build_extra_plans(assessment, selected_extras, python_version, architecture)
    configuration = [
        ConfigurationPlan(
            name=item.name,
            secret=item.secret,
            required_at_launch=item.required_at_launch,
            supply_strategy=(
                "existing_application_workflow"
                if item.secret
                and item.required_at_launch is not True
                and entry_point is not None
                and entry_point.kind == "gui"
                else "environment"
                if item.kind == "environment_variable"
                else "manual_review"
            ),
            rationale=(
                "Keep the GUI's existing optional/session configuration workflow; record presence "
                "only and validate that launch does not require the secret."
                if item.secret
                and item.required_at_launch is not True
                and entry_point is not None
                and entry_point.kind == "gui"
                else "Supply configuration outside metadata and never record secret values."
            ),
        )
        for item in assessment.configuration_requirements
    ]
    project_writes = [
        item.path_expression
        for item in assessment.write_locations
        if item.classification == "project_local"
    ]
    writes = WritePolicyPlan(
        requires_project_write_probe=bool(project_writes),
        project_local_locations=project_writes,
        failure_policy=(
            "Fail clearly without elevation and direct the user to a writable extraction/output "
            "location."
            if project_writes
            else "No project-root write probe is required by static evidence."
        ),
    )
    decisions = [
        PlanningDecision(
            topic="deployment_mode",
            selected=mode,
            rationale=mode_rationale,
            alternatives=["package", "source_resource_copy"],
        ),
        PlanningDecision(
            topic="python_version",
            selected=python_version,
            rationale="Selected from metadata plus requested wheel evidence.",
            alternatives=[item.version for item in python_candidates if not item.selected],
        ),
        PlanningDecision(
            topic="runtime_backend",
            selected="uv_managed",
            rationale="Use pinned uv and managed CPython, never an unknown system interpreter.",
            alternatives=["existing_python", "offline_bundle", "custom_runtime"],
        ),
        PlanningDecision(
            topic="entry_point",
            selected=entry_point.name if entry_point else "declaration required",
            rationale=(
                "Prefer a declared GUI entry point for the end-user launcher when available."
                if entry_point
                else (
                    "Candidate launchers remain diagnostic until standardized metadata declares "
                    "authority."
                )
            ),
            alternatives=(
                entry_point.alternatives
                if entry_point
                else [item.target or item.path for item in assessment.entry_point_candidates]
            ),
        ),
        PlanningDecision(
            topic="selected_extras",
            selected=", ".join(selected_extras) or "none",
            rationale="Only extras explicitly selected by the deployment developer are installed.",
            alternatives=[item.name for item in extras if not item.selected],
        ),
    ]
    gate = _risk_gate(assessment)
    fingerprint = hashlib.sha256(
        json.dumps(sorted(selected_extras), separators=(",", ":")).encode()
    ).hexdigest()
    limitations = [
        "Lockfile currentness is not assumed from existence; developer preparation must run "
        "uv lock --check.",
        "No source distribution is built during assessment or planning.",
        "Bootstrap implementation, fast-path, repair, and diagnostics remain Milestone 3.",
        "Runtime installation and target execution require explicit Milestone 4 validation.",
    ]
    if not online:
        limitations.append("Online package-index compatibility inspection was not requested.")
    if repository_root is None:
        limitations.append("No repository root was supplied for static uv.lock graph inspection.")
    external_runtimes = external_runtime_requirements(applicable_dependencies, selected_extras)
    validation_requirements = [
        "Run uv lock --check before generation; do not rewrite the lockfile on the end-user PC.",
        "Verify imports in an isolated Windows environment without paid or destructive calls.",
        (
            "Perform the GUI smoke test manually."
            if entry_point and entry_point.kind == "gui"
            else "Declare an authoritative entry point before application launch validation."
        ),
        *[
            f"Detect {item.name} for selected feature '{item.feature}'."
            for item in external_runtimes
        ],
        *(["Probe project/output write access before launch."] if project_writes else []),
    ]
    return DeploymentPlan(
        generated_at=datetime.now(UTC),
        tool_version=__version__,
        assessment_repository_fingerprint=assessment.repository.fingerprint,
        application_id=app_id,
        application_display_name=name.replace("-", " ").title(),
        deployment_mode=mode,
        deployment_mode_condition=mode_condition,
        runtime=runtime,
        entry_point=entry_point,
        lockfile=lockfile,
        lock_graph=lock_graph,
        risk_gate=gate,
        readiness=_readiness(
            gate,
            lockfile,
            lock_graph,
            entry_point,
            mode,
            mode_blockers,
        ),
        extras=extras,
        selected_extras_fingerprint=fingerprint,
        external_runtimes=external_runtimes,
        vendor_runtimes=assessment.vendor_runtimes,
        platform_findings=windows_finding_treatments(assessment.runtime_requirements),
        shell_policy=windows_shell_policy(),
        bootstrap=windows_bootstrap_plan(),
        python_candidates=python_candidates,
        configuration=configuration,
        writes=writes,
        decisions=decisions,
        online_compatibility=compatibility,
        validation_requirements=validation_requirements,
        limitations=limitations,
        structural_guidance=assessment.structural_guidance,
        application_version=assessment.project.version,
        repository_revision=assessment.repository.revision,
    )
