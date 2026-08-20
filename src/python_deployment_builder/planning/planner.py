"""Convert repository facts into an explicit deployment policy."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.backends.uv_managed import UvManagedBackend
from python_deployment_builder.models import (
    ConfigurationPlan,
    DeploymentPlan,
    DeploymentReadiness,
    EntrypointPlan,
    LockfilePlan,
    OnlineCompatibilityAssessment,
    PlannedCommand,
    PlanningDecision,
    PythonCandidatePlan,
    RepositoryAssessment,
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
    candidate_python_versions,
    python_satisfies,
    safe_application_id,
)


def _deployment_mode(assessment: RepositoryAssessment) -> tuple[str, str]:
    adjacent = any(item.packaging_status == "repository_adjacent" for item in assessment.resources)
    project_writes = any(
        item.classification == "project_local" for item in assessment.write_locations
    )
    if adjacent or project_writes:
        return (
            "source",
            "Repository-adjacent resources or project-local writes make an extracted-source "
            "layout the safest initial policy.",
        )
    return "package", "No repository-adjacent runtime dependency requires a source layout."


def _entrypoint(assessment: RepositoryAssessment) -> EntrypointPlan:
    entries = assessment.project.entry_points
    if not entries:
        raise ValueError("No standardized application entry point was detected.")
    chosen = next((item for item in entries if item.kind == "gui"), entries[0])
    if ":" not in chosen.target:
        raise ValueError(f"Entry point target is not module:callable: {chosen.target}")
    module, callable_name = chosen.target.split(":", 1)
    return EntrypointPlan(
        name=chosen.name,
        target=chosen.target,
        kind=chosen.kind,
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
        satisfies = python_satisfies(version, assessment.python.requires_python)
        compatibility = "viable" if satisfies else "incompatible"
        rationale = (
            "Satisfies declared Python metadata."
            if satisfies
            else "Does not satisfy the declared requires-python constraint."
        )
        if satisfies and online:
            checked = [item for item in online.dependencies if item.python_version == version]
            missing = sorted(
                item.distribution_name for item in checked if item.wheel_available is False
            )
            if online.errors or not checked:
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
) -> DeploymentReadiness:
    blockers: list[str] = []
    pending: list[str] = []
    resolved = ["Python runtime selected", "Source/package mode selected"]
    if assessment_gate.outcome == "block":
        blockers.extend(assessment_gate.blocking_codes)
    if lockfile.status == "developer_generation_required":
        blockers.append("LOCKFILE_GENERATION_REQUIRED")
    else:
        pending.append("LOCKFILE_CURRENTNESS_UNVERIFIED")
    if lock_graph and lock_graph.artifact_findings:
        blockers.extend(
            f"DEVELOPER_ARTIFACT_REQUIRED:{item.package}=={item.version}"
            for item in lock_graph.artifact_findings
        )
    if assessment_gate.outcome == "block":
        state = "BLOCKED"
    elif lock_graph and lock_graph.artifact_findings:
        state = "BLOCKED_PENDING_DEVELOPER_ARTIFACT"
    elif lockfile.status == "developer_generation_required":
        state = "BLOCKED_PENDING_LOCKFILE"
    elif pending:
        state = "BLOCKED_PENDING_LOCK_VERIFICATION"
    else:
        state = "VALIDATION_REQUIRED"
    return DeploymentReadiness(
        state=state,
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
    inspection_dependencies = [
        item
        for item in assessment.dependencies
        if item.group == "runtime" or item.group in selected_extras
    ]
    versions = candidate_python_versions(assessment)
    compatibility = (
        inspect_dependency_wheels(inspection_dependencies, versions, architecture)
        if online
        else None
    )
    python_version, python_candidates = _python_candidates(assessment, compatibility)
    name = assessment.project.distribution_name or assessment.repository.root_name
    app_id = safe_application_id(name)
    mode, mode_rationale = _deployment_mode(assessment)
    entry_point = _entrypoint(assessment)
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
            selected=entry_point.name,
            rationale="Prefer a declared GUI entry point for the end-user launcher when available.",
            alternatives=entry_point.alternatives,
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
        "Perform the GUI smoke test manually.",
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
        runtime=runtime,
        entry_point=entry_point,
        lockfile=lockfile,
        lock_graph=lock_graph,
        risk_gate=gate,
        readiness=_readiness(gate, lockfile, lock_graph),
        extras=extras,
        selected_extras_fingerprint=fingerprint,
        external_runtimes=external_runtimes,
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
    )
