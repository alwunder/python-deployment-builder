"""Developer-focused Markdown rendering for assessments."""

from __future__ import annotations

from python_deployment_builder.models import DeploymentPlan, Evidence, RepositoryAssessment


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _evidence(evidence: list[Evidence]) -> str:
    rendered: list[str] = []
    for item in evidence[:4]:
        location = f"{item.file}:{item.line}" if item.line else item.file
        rendered.append(f"`{location}` — {item.detail}")
    return "; ".join(rendered) or "—"


def render_assessment_markdown(assessment: RepositoryAssessment) -> str:
    project = assessment.project
    lines = [
        "# Static deployment assessment",
        "",
        f"**Rating: {assessment.rating.value}** — {assessment.rating_summary}",
        "",
        f"- Schema version: `{assessment.schema_version}`",
        f"- Generated: `{assessment.generated_at.isoformat()}`",
        f"- Repository source: `{assessment.repository.source}`",
        f"- Repository fingerprint: `{assessment.repository.fingerprint}`",
        f"- Project: `{project.distribution_name or assessment.repository.root_name}`",
        f"- Packaging layout: `{project.layout}`",
        "",
        "## Packaging and entry points",
        "",
    ]
    if project.entry_points:
        lines.extend(["| Name | Kind | Target |", "|---|---|---|"])
        lines.extend(
            f"| `{_escape(item.name)}` | {item.kind} | `{_escape(item.target)}` |"
            for item in project.entry_points
        )
    else:
        lines.append("No standardized entry points were detected.")
    lines.extend(
        [
            "",
            "## Python requirements",
            "",
            f"- `requires-python`: `{assessment.python.requires_python or 'not declared'}`",
            f"- `.python-version`: `{assessment.python.python_version_file or 'not present'}`",
            f"- Ruff target: `{assessment.python.ruff_target_version or 'not configured'}`",
            "- Documented versions: `"
            + (", ".join(assessment.python.documented_versions) or "none detected")
            + "`",
            "",
            "The assessment records compatibility evidence only. Runtime selection is a "
            "planner policy decision.",
            "",
            "## Declared dependencies",
            "",
            "| Distribution | Constraint | Group | Imports | Implementation | Windows concern "
            "| Wheel status |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in assessment.dependencies:
        lines.append(
            f"| `{_escape(item.distribution_name)}` | `{_escape(item.declared_constraint)}` | "
            f"{_escape(item.group)} | `{_escape(', '.join(item.import_names))}` | "
            f"{item.implementation} | {item.windows_concern} | {item.wheel_status} |"
        )
    if assessment.declared_but_apparently_unused:
        lines.extend(
            [
                "",
                "Declared but apparently unused by application-source imports: "
                + ", ".join(f"`{item}`" for item in assessment.declared_but_apparently_unused)
                + ". This is heuristic.",
            ]
        )
    undeclared = [
        item
        for item in assessment.imports
        if item.classification == "observed_undeclared_third_party"
    ]
    lines.extend(["", "## Import mismatches", ""])
    if undeclared:
        for item in undeclared:
            lines.append(f"- `{item.import_name}` ({_evidence(item.evidence)})")
    else:
        lines.append(
            "No observed application-source imports were left unmatched to the standard library, "
            "local modules, or declared dependencies."
        )

    lines.extend(["", "## Runtime assumptions", ""])
    for item in assessment.runtime_requirements:
        lines.append(
            f"- **{item.status.value} — {item.category}: {item.name}.** "
            f"{item.description} Evidence: {_evidence(item.evidence)}"
        )
    if not assessment.runtime_requirements:
        lines.append("No notable runtime assumptions were detected.")

    lines.extend(["", "## Repository resources", ""])
    for item in assessment.resources:
        lines.append(
            f"- **{item.status.value}: `{item.path}`** — {item.kind}; "
            f"{item.packaging_status}; {item.access_mode}. Evidence: {_evidence(item.evidence)}"
        )
    if not assessment.resources:
        lines.append("No conventional resource directories or files were detected.")

    lines.extend(["", "## Runtime writes", ""])
    for item in assessment.write_locations:
        lines.append(
            f"- **{item.status.value}: {item.classification}** — "
            f"`{_escape(item.path_expression)}`. "
            f"Evidence: {_evidence(item.evidence)}"
        )
    if not assessment.write_locations:
        lines.append("No write-capable calls were detected in application source.")

    lines.extend(["", "## Configuration and secrets", ""])
    for item in assessment.configuration_requirements:
        secret = "secret-bearing" if item.secret else "non-secret or example"
        lines.append(
            f"- **{item.status.value}: `{item.name}`** — {item.kind}, {secret}. "
            f"{item.description} Evidence: {_evidence(item.evidence)}"
        )
    if not assessment.configuration_requirements:
        lines.append("No configuration requirements were detected.")

    lines.extend(["", "## Risks and recommendations", ""])
    for item in assessment.risks:
        lines.append(f"### {item.severity.value.upper()}: {item.title} (`{item.code}`)")
        lines.extend(["", item.description, ""])
        if item.recommendation:
            lines.append(f"Recommendation: {item.recommendation}")
            lines.append("")
        if item.evidence:
            lines.append(f"Evidence: {_evidence(item.evidence)}")
            lines.append("")
    if not assessment.risks:
        lines.append("No material static deployment risks were identified.")

    lines.extend(["", "## Analysis boundaries", ""])
    lines.extend(f"- {item}" for item in assessment.analysis_limitations)
    lines.append("")
    return "\n".join(lines)


def render_deployment_plan_markdown(plan: DeploymentPlan) -> str:
    """Render policy decisions and their evidence-facing consequences."""

    runtime = plan.runtime
    lines = [
        "# Deployment plan",
        "",
        f"**Gate: {plan.risk_gate.outcome.replace('_', ' ').upper()}** — "
        f"{plan.risk_gate.rationale}",
        "",
        f"- Schema version: `{plan.schema_version}`",
        f"- Generated: `{plan.generated_at.isoformat()}`",
        f"- Application: `{plan.application_display_name}` (`{plan.application_id}`)",
        f"- Assessment fingerprint: `{plan.assessment_repository_fingerprint}`",
        f"- Deployment mode: `{plan.deployment_mode}`",
        f"- Entry point: `{plan.entry_point.name}` → `{plan.entry_point.target}`",
        "",
        "## Decisions",
        "",
    ]
    for decision in plan.decisions:
        lines.extend(
            [
                f"### {decision.topic.replace('_', ' ').title()}: `{decision.selected}`",
                "",
                decision.rationale,
                "",
                "Alternatives: "
                + (", ".join(f"`{item}`" for item in decision.alternatives) or "none"),
                "",
            ]
        )
    lines.extend(
        [
            "## Python candidates",
            "",
            "| Version | Selected | Metadata | Compatibility | Rationale |",
            "|---|---|---|---|---|",
        ]
    )
    for item in plan.python_candidates:
        lines.append(
            f"| `{item.version}` | {'yes' if item.selected else 'no'} | "
            f"{'satisfies' if item.satisfies_requires_python else 'rejects'} | "
            f"{item.compatibility} | {_escape(item.rationale)} |"
        )
    lines.extend(
        [
            "",
            "## Managed runtime",
            "",
            f"- Backend: `{runtime.backend}`",
            f"- Windows architecture: `{runtime.architecture}`",
            f"- Python minor: `{runtime.python_version}`",
            f"- Pinned uv: `{runtime.uv_version}`",
            f"- uv archive: `{runtime.bootstrap_artifact.url}`",
            f"- uv SHA-256: `{runtime.bootstrap_artifact.sha256}`",
            f"- Shared root: `{runtime.paths.shared_root}`",
            f"- Application environment: `{runtime.paths.environment_path}`",
            "- PATH and Windows registry integration: disabled",
            "- Source builds during end-user sync: disabled",
            "",
            "### Planned commands",
            "",
            f"- Provision: `{runtime.provision_command.executable} "
            + " ".join(runtime.provision_command.arguments)
            + "`",
            f"- Frozen sync: `{runtime.sync_command.executable} "
            + " ".join(runtime.sync_command.arguments)
            + "`",
        ]
    )
    if runtime.application_install_command:
        command = runtime.application_install_command
        lines.append(
            f"- Application install: `{command.executable} {' '.join(command.arguments)}`"
        )
    lines.extend(
        [
            "",
            "## Lockfile policy",
            "",
            f"- Status: `{plan.lockfile.status}`",
            f"- End-user policy: `{plan.lockfile.end_user_policy}`",
            f"- End-user updates allowed: `{str(plan.lockfile.allow_end_user_update).lower()}`",
        ]
    )
    if plan.lockfile.developer_commands:
        lines.append("- Developer preparation:")
        for command in plan.lockfile.developer_commands:
            lines.append(
                f"  - `{command.executable} {' '.join(command.arguments)}` — {command.purpose}"
            )
    lines.extend(["", "## Risk treatment", ""])
    lines.append(
        "- Warnings: "
        + (", ".join(f"`{item}`" for item in plan.risk_gate.warning_codes) or "none")
    )
    lines.append(
        "- Blocking findings: "
        + (", ".join(f"`{item}`" for item in plan.risk_gate.blocking_codes) or "none")
    )
    lines.extend(["", "## Configuration and writes", ""])
    for item in plan.configuration:
        lines.append(
            f"- `{item.name}` — `{item.supply_strategy}`; value persisted: "
            f"`{str(item.persist_value).lower()}`; value logged: `{str(item.log_value).lower()}`. "
            f"{item.rationale}"
        )
    if not plan.configuration:
        lines.append("- No configuration requirements were detected.")
    lines.append(
        "- Project write probe required: "
        f"`{str(plan.writes.requires_project_write_probe).lower()}`. "
        + plan.writes.failure_policy
    )
    if plan.online_compatibility:
        context = plan.online_compatibility.context
        lines.extend(
            [
                "",
                "## Online wheel inspection",
                "",
                f"- Assessed: `{context.assessed_at.isoformat()}`",
                f"- Source: `{context.index_name}` (`{context.index_url}`)",
                f"- Targets: `{', '.join(context.python_targets)}` / "
                f"`{context.windows_architecture}`",
                "",
                "| Distribution | Release | Python | Wheel |",
                "|---|---|---|---|",
            ]
        )
        for item in plan.online_compatibility.dependencies:
            lines.append(
                f"| `{item.distribution_name}` | `{item.resolved_version or 'unresolved'}` | "
                f"`{item.python_version}` | "
                f"{'available' if item.wheel_available else 'not detected'} |"
            )
        for error in plan.online_compatibility.errors:
            lines.append(f"- Inspection error: {_escape(error)}")
    lines.extend(["", "## Required validation", ""])
    lines.extend(f"- {item}" for item in plan.validation_requirements)
    lines.extend(["", "## Planning boundaries", ""])
    lines.extend(f"- {item}" for item in plan.limitations)
    lines.append("")
    return "\n".join(lines)
