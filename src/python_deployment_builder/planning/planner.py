"""Convert repository facts into an explicit deployment policy."""

from __future__ import annotations

from datetime import UTC, datetime

from python_deployment_builder import __version__
from python_deployment_builder.backends.uv_managed import UvManagedBackend
from python_deployment_builder.models import (
    ConfigurationPlan,
    DeploymentPlan,
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
from python_deployment_builder.planning.index import inspect_dependency_wheels
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
            rationale=(
                "The deployment may proceed if generated checks preserve the listed safeguards."
            ),
        )
    return RiskGate(
        outcome="allow",
        rationale="No blocking or warning-level assessment risks remain.",
    )


def _python_candidates(
    assessment: RepositoryAssessment,
    online: OnlineCompatibilityAssessment | None,
) -> tuple[str, list[PythonCandidatePlan]]:
    versions = candidate_python_versions(assessment)
    candidates: list[PythonCandidatePlan] = []
    viable: list[str] = []
    for version in versions:
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
                compatibility = "incompatible"
                rationale += " No compatible wheel was detected for: " + ", ".join(missing) + "."
            else:
                rationale += (
                    " All inspected direct runtime dependencies publish compatible wheels."
                )
        elif satisfies:
            compatibility = "unverified"
            rationale += " Windows wheel availability was not queried."
        if satisfies and compatibility != "incompatible":
            viable.append(version)
        candidates.append(
            PythonCandidatePlan(
                version=version,
                satisfies_requires_python=satisfies,
                compatibility=compatibility,
                rationale=rationale,
            )
        )
    if not viable:
        raise ValueError(
            "No Python policy candidate satisfies project and wheel compatibility evidence."
        )
    selected = viable[0]
    for candidate in candidates:
        candidate.selected = candidate.version == selected
        if candidate.selected:
            candidate.rationale += " Selected by the policy preference order."
    return selected, candidates


def create_deployment_plan(
    assessment: RepositoryAssessment,
    *,
    architecture: str = "x86_64",
    online: bool = False,
) -> DeploymentPlan:
    """Plan only: no target code, downloads, lock updates, or environment mutations occur."""

    versions = candidate_python_versions(assessment)
    compatibility = (
        inspect_dependency_wheels(assessment.dependencies, versions, architecture)
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
    )
    lock_present = "uv.lock" in assessment.project.lockfiles
    lockfile = LockfilePlan(
        status="present" if lock_present else "developer_generation_required",
        developer_commands=(
            []
            if lock_present
            else [
                PlannedCommand(
                    executable=runtime.paths.uv_executable,
                    arguments=["lock", "--python", python_version],
                    working_directory="%PROJECT_ROOT%",
                    purpose="Generate the application lockfile during developer-side preparation.",
                ),
                PlannedCommand(
                    executable=runtime.paths.uv_executable,
                    arguments=["lock", "--check"],
                    working_directory="%PROJECT_ROOT%",
                    purpose="Verify the committed lockfile matches project metadata.",
                ),
            ]
        ),
    )
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
                "Keep the GUI's existing optional/session configuration workflow; record "
                "presence only and validate that launch does not require the secret."
                if item.secret
                and item.required_at_launch is not True
                and entry_point.kind == "gui"
                else (
                    "Supply configuration outside deployment metadata and never record "
                    "secret values."
                )
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
            "Fail clearly without elevation and direct the user to a writable "
            "extraction/output location."
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
            rationale=(
                "Selected independently from assessment facts using the managed-runtime policy "
                "and wheel evidence when requested."
            ),
            alternatives=[
                item.version
                for item in python_candidates
                if not item.selected and item.satisfies_requires_python
            ],
        ),
        PlanningDecision(
            topic="runtime_backend",
            selected="uv_managed",
            rationale=(
                "Use pinned uv and managed CPython rather than an unknown system interpreter."
            ),
            alternatives=["existing_python", "offline_bundle", "custom_runtime"],
        ),
        PlanningDecision(
            topic="entry_point",
            selected=entry_point.name,
            rationale="Prefer a declared GUI entry point for the end-user launcher when available.",
            alternatives=entry_point.alternatives,
        ),
    ]
    limitations = [
        "The plan does not mutate the repository or generate the missing uv.lock.",
        "End-user bootstrap, fast-path, repair, diagnostics, and template rendering are "
        "Milestone 3.",
        "Runtime installation and target execution require explicit Milestone 4 validation.",
    ]
    if not online:
        limitations.append("Online package-index compatibility inspection was not requested.")
    else:
        limitations.append(
            "Online inspection covers declared direct dependencies; lock/runtime validation must "
            "verify transitive dependencies such as native extension helpers."
        )
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
        risk_gate=_risk_gate(assessment),
        python_candidates=python_candidates,
        configuration=configuration,
        writes=writes,
        decisions=decisions,
        online_compatibility=compatibility,
        validation_requirements=[
            "Verify the committed uv.lock is current before generation.",
            *(
                ["Build and verify the application wheel during developer-side preparation."]
                if mode != "source"
                else []
            ),
            "Verify imports in the isolated Windows environment without making paid API calls.",
            "Perform the GUI smoke test manually.",
            *(
                [
                    "Confirm the GUI launches without secret configuration and retains its "
                    "session-entry workflow."
                ]
                if any(item.secret for item in assessment.configuration_requirements)
                and entry_point.kind == "gui"
                else []
            ),
            *(
                ["Probe project/output write access before launch."]
                if project_writes
                else []
            ),
        ],
        limitations=limitations,
    )
