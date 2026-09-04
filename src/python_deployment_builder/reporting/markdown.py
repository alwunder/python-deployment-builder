"""Developer-focused Markdown rendering for assessments."""

from __future__ import annotations

from python_deployment_builder.models import (
    DeploymentPlan,
    Evidence,
    RepositoryAssessment,
    ValidationReport,
)


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
        "- Deployment-input repository fingerprint: "
        f"`{assessment.repository.fingerprint}` (`{assessment.repository.fingerprint_scope}`)",
        f"- Project: `{project.distribution_name or assessment.repository.root_name}`",
        f"- Packaging layout: `{project.layout}`",
        "",
        "## Analysis scope",
        "",
        "- Application source files analyzed: "
        f"`{assessment.analysis_scope.application_source_files}`",
        f"- Runtime resources detected: `{assessment.analysis_scope.runtime_resources}`",
        f"- Deployment-support files: `{assessment.analysis_scope.deployment_support_files}`",
        f"- Tests excluded from runtime scan: `{assessment.analysis_scope.tests_excluded}`",
        f"- Documentation excluded: `{assessment.analysis_scope.documentation_excluded}`",
        f"- Examples/snippets excluded: `{assessment.analysis_scope.examples_excluded}`",
        f"- Ignored/local paths excluded: `{assessment.analysis_scope.ignored_local_excluded}`",
        f"- Unknown-role files: `{assessment.analysis_scope.unknown_role_files}`",
        "",
        "## Packaging and entry points",
        "",
    ]
    if project.entry_points:
        lines.extend(["| Name | Declared group | Launch kind | Target |", "|---|---|---|---|"])
        lines.extend(
            f"| `{_escape(item.name)}` | `{item.declared_group}` | {item.kind} | "
            f"`{_escape(item.target)}` |"
            for item in project.entry_points
        )
    else:
        lines.append("No standardized entry points were detected.")
    if assessment.entry_point_candidates:
        lines.extend(["", "### Diagnostic entry-point candidates", ""])
        for item in assessment.entry_point_candidates:
            lines.append(
                f"- `{item.path}` -> `{item.target or 'unresolved'}`; {item.kind}; "
                f"confidence `{item.confidence}`; **candidate only, not authoritative**. "
                f"Evidence: {_evidence(item.evidence)}"
            )
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
            "| Distribution | Constraint | Marker | Group | Imports | Implementation | "
            "Windows concern | Wheel status |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for item in assessment.dependencies:
        lines.append(
            f"| `{_escape(item.distribution_name)}` | `{_escape(item.declared_constraint)}` | "
            f"`{_escape(item.environment_marker or 'all')}` | {_escape(item.group)} | "
            f"`{_escape(', '.join(item.import_names))}` | "
            f"{item.implementation} | {item.windows_concern} | {item.wheel_status} |"
        )
    if project.legacy_dependency_groups:
        lines.extend(["", "### Legacy requirements-file groups", ""])
        for group in project.legacy_dependency_groups:
            relationships = ", ".join(group.aggregate_of) or "none detected"
            lines.append(
                f"- `{group.name}` from `{group.source_file}`; aggregate/includes: "
                f"`{relationships}`; authoritative selectable extra: `false`."
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
    contextual = [item for item in assessment.imports if item.contexts != ["module_top_level"]]
    if contextual:
        lines.extend(["", "### Import context evidence", ""])
        for item in contextual:
            lines.append(
                f"- `{item.import_name}`: `{', '.join(item.contexts)}`; "
                f"launch-critical status is not inferred from a deferred/type-only import alone. "
                f"Evidence: {_evidence(item.evidence)}"
            )

    lines.extend(["", "## Existing deployment support", ""])
    if assessment.deployment_support:
        for item in assessment.deployment_support:
            lines.append(
                f"- **{item.category}: {item.name}** - {item.description} "
                f"Evidence: {_evidence(item.evidence)}"
            )
    else:
        lines.append("No existing deployment-support architecture was detected.")
    if assessment.deployment_support_dependencies:
        lines.extend(["", "### Deployment-support-only dependency constraints", ""])
        for dependency in assessment.deployment_support_dependencies:
            lines.append(
                f"- `{dependency.distribution_name}{dependency.declared_constraint}` - "
                "informational only; not an application launch dependency or selectable extra. "
                f"Evidence: {_evidence(dependency.evidence)}"
            )
    if assessment.vendor_runtimes:
        lines.extend(["", "### External/vendor runtime evidence", ""])
        for item in assessment.vendor_runtimes:
            lines.append(
                f"- **{item.name}** - backend supported: "
                f"`{str(item.backend_supported).lower()}`; core-launch requirement: "
                f"`{item.required_for_core_launch}`. {item.description} "
                f"Evidence: {_evidence(item.evidence)}"
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

    lines.extend(["", "## Structural guidance", ""])
    for item in assessment.structural_guidance:
        lines.extend(
            [
                f"### {item.classification.value.upper()}: {item.title} (`{item.code}`)",
                "",
                item.explanation,
                "",
                f"Why it matters: {item.why_it_matters}",
                "",
            ]
        )
        if item.suggested_direction:
            lines.extend([f"Suggested direction: {item.suggested_direction}", ""])
        if item.evidence:
            lines.extend([f"Evidence: {_evidence(item.evidence)}", ""])

    lines.extend(["", "## Analysis boundaries", ""])
    lines.extend(f"- {item}" for item in assessment.analysis_limitations)
    lines.append("")
    return "\n".join(lines)


def render_deployment_plan_markdown(plan: DeploymentPlan) -> str:
    """Render policy decisions and their evidence-facing consequences."""

    runtime = plan.runtime
    entry_point_summary = (
        f"`{plan.entry_point.name}` -> `{plan.entry_point.target}`"
        if plan.entry_point
        else "`declaration required` (diagnostic candidates are non-authoritative)"
    )
    lines = [
        "# Deployment plan",
        "",
        f"**Gate: {plan.risk_gate.outcome.replace('_', ' ').upper()}** — "
        f"{plan.risk_gate.rationale}",
        "",
        f"- Schema version: `{plan.schema_version}`",
        f"- Generated: `{plan.generated_at.isoformat()}`",
        f"- Application: `{plan.application_display_name}` (`{plan.application_id}`)",
        f"- Assessment deployment-input fingerprint: `{plan.assessment_repository_fingerprint}`",
        f"- Deployment mode: `{plan.deployment_mode}`",
        f"- Entry point: {entry_point_summary}",
        f"- Deployment readiness: `{plan.readiness.state}`",
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
            f"- Locked sync: `{runtime.sync_command.executable} "
            + " ".join(runtime.sync_command.arguments)
            + "`",
        ]
    )
    if runtime.application_install_command:
        command = runtime.application_install_command
        lines.append(f"- Application install: `{command.executable} {' '.join(command.arguments)}`")
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
    lines.extend(["", "## Optional features", ""])
    if plan.extras:
        lines.extend(
            [
                "| Extra | Recommended | Selected | Applicable dependencies | Policy |",
                "|---|---|---|---|---|",
            ]
        )
        for extra in plan.extras:
            dependencies = ", ".join(
                item.distribution_name for item in extra.dependencies if item.platform_applicable
            )
            lines.append(
                f"| `{extra.name}` | {'yes' if extra.recommended else 'no'} | "
                f"{'yes' if extra.selected else 'no'} | `{dependencies or 'none'}` | "
                f"{_escape(extra.selection_reason)} |"
            )
            if extra.recommendation_reason:
                lines.append(f"- Recommendation for `{extra.name}`: {extra.recommendation_reason}")
    else:
        lines.append("No optional dependency extras are declared.")
    lines.extend(["", "## PowerShell-free bootstrap policy", ""])
    lines.extend(
        [
            f"- Preferred mode: `{plan.bootstrap.preferred_mode}`",
            "- Command prompt required: "
            f"`{str(plan.shell_policy.command_prompt_required).lower()}`",
            f"- PowerShell allowed: `{str(plan.shell_policy.powershell_allowed).lower()}`",
            "- TLS verification required: "
            f"`{str(plan.bootstrap.tls_verification_required).lower()}`",
            f"- Security bypass allowed: `{str(plan.bootstrap.allow_security_bypass).lower()}`",
        ]
    )
    for mode in plan.bootstrap.modes:
        tools = ", ".join(item.executable for item in mode.required_host_tools) or "none"
        lines.append(
            f"- `{mode.mode}` ({mode.status}): network={str(mode.requires_network).lower()}; "
            f"host tools: `{tools}`. {mode.description}"
        )
        for tool in mode.required_host_tools:
            lines.append(
                f"  - `{tool.executable}`: {tool.purpose} "
                "Execution preflight required: "
                f"`{str(tool.must_preflight_execution).lower()}`."
            )
    lines.append(f"- Unavailable policy: {plan.bootstrap.unavailable_policy}")
    if plan.lock_graph:
        lines.extend(["", "## Locked dependency artifacts", ""])
        if plan.lock_graph.dependencies:
            lines.extend(
                [
                    "| Package | Version | Direct | Feature | Chain | Artifact policy |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for dependency in plan.lock_graph.dependencies:
                lines.append(
                    f"| `{dependency.name}` | `{dependency.version}` | "
                    f"{'yes' if dependency.direct else 'no'} | "
                    f"`{dependency.selected_extra or 'core'}` | "
                    f"`{' → '.join(dependency.dependency_chain)}` | "
                    f"`{dependency.artifact.policy}` |"
                )
        else:
            lines.append("No locked dependencies were resolved for the selected feature set.")
        for finding in plan.lock_graph.artifact_findings:
            lines.extend(
                [
                    "",
                    f"### Developer artifact required: `{finding.package}=={finding.version}`",
                    "",
                    finding.description,
                    "",
                    f"Dependency chain: `{' → '.join(finding.dependency_chain)}`",
                    f"Selected feature: `{finding.selected_extra or 'core'}`",
                ]
            )
    lines.extend(["", "## External runtimes", ""])
    if plan.external_runtimes:
        for requirement in plan.external_runtimes:
            lines.append(
                f"- **{requirement.status.value}: {requirement.name}** — platform "
                f"`{requirement.platform}`; launch required: "
                f"`{str(requirement.required_at_launch).lower()}`; feature "
                f"`{requirement.feature or 'core'}` required: "
                f"`{str(requirement.required_for_feature).lower()}`. "
                f"{requirement.detection_strategy} Automatic installation: "
                f"`{requirement.automatic_installation_policy}`."
            )
    else:
        lines.append("No external runtime requirement applies to the selected features.")
    if plan.vendor_runtimes:
        lines.extend(["", "### Vendor runtime evidence (not a selected backend)", ""])
        for requirement in plan.vendor_runtimes:
            lines.append(
                f"- **{requirement.name}** - backend supported: "
                f"`{str(requirement.backend_supported).lower()}`; core-launch requirement: "
                f"`{requirement.required_for_core_launch}`. {requirement.description}"
            )
    lines.extend(["", "## Windows platform applicability", ""])
    if plan.platform_findings:
        lines.extend(
            [
                "| Finding | Platforms | Treatment | Rationale |",
                "|---|---|---|---|",
            ]
        )
        for finding in plan.platform_findings:
            lines.append(
                f"| `{finding.category}: {finding.name}` | "
                f"`{', '.join(finding.platforms)}` | `{finding.decision}` | "
                f"{_escape(finding.rationale)} |"
            )
    else:
        lines.append("No platform-specific runtime findings were detected.")
    lines.extend(["", "## Risk treatment", ""])
    lines.append(
        "- Warnings: " + (", ".join(f"`{item}`" for item in plan.risk_gate.warning_codes) or "none")
    )
    lines.append(
        "- Blocking findings: "
        + (", ".join(f"`{item}`" for item in plan.risk_gate.blocking_codes) or "none")
    )
    lines.append(
        "- Readiness blockers: "
        + (", ".join(f"`{item}`" for item in plan.readiness.blockers) or "none")
    )
    lines.append(
        "- Readiness pending: "
        + (", ".join(f"`{item}`" for item in plan.readiness.pending) or "none")
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
        f"`{str(plan.writes.requires_project_write_probe).lower()}`. " + plan.writes.failure_policy
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
                "| Distribution | Release | Python | Wheel | Selection meaning |",
                "|---|---|---|---|---|",
            ]
        )
        for item in plan.online_compatibility.dependencies:
            lines.append(
                f"| `{item.distribution_name}` | `{item.resolved_version or 'unresolved'}` | "
                f"`{item.python_version}` | "
                f"{'available' if item.wheel_available else 'not detected'} | "
                f"`{item.deployment_selection}` |"
            )
        for error in plan.online_compatibility.errors:
            lines.append(f"- Inspection error: {_escape(error)}")
    lines.extend(["", "## Required validation", ""])
    lines.extend(f"- {item}" for item in plan.validation_requirements)
    lines.extend(["", "## Planning boundaries", ""])
    lines.extend(f"- {item}" for item in plan.limitations)
    lines.extend(["", "## Structural guidance carried from assessment", ""])
    for item in plan.structural_guidance:
        lines.append(
            f"- **{item.classification.value}: {item.title}** (`{item.code}`) - {item.explanation}"
        )
    lines.append("")
    return "\n".join(lines)


def render_validation_markdown(report: ValidationReport) -> str:
    """Render a concise developer-facing validation report."""

    lines = [
        f"# Validation: {report.application_display_name}",
        "",
        f"- Final state: **{report.final_state.value}**",
        f"- Mode: `{report.validation_mode}`",
        f"- Deployment fingerprint: `{report.deployment_fingerprint}`",
        f"- Validated: `{report.generated_at.isoformat()}`",
        f"- Host: `{report.host.hostname}` / `{report.host.operating_system}` / "
        f"`{report.host.architecture}`",
        f"- Kit: `{report.kit_root}`",
        f"- Runtime root: `{report.runtime_root or 'not used'}`",
        "",
        "## Static checks",
        "",
        "| Status | Check | Detail |",
        "|---|---|---|",
    ]
    for check in report.static_checks:
        lines.append(f"| {check.status.value} | `{check.code}` | {_escape(check.detail)} |")
        lines.extend(f"  - Evidence: `{item}`" for item in check.evidence)
    lines.extend(["", "## Runtime checks", ""])
    if report.runtime_checks:
        lines.extend(["| Status | Phase | Check | Detail |", "|---|---|---|---|"])
        for check in report.runtime_checks:
            duration = (
                f" ({check.duration_seconds:.2f}s)" if check.duration_seconds is not None else ""
            )
            lines.append(
                f"| {check.status.value} | `{check.phase}` | `{check.code}` | "
                f"{_escape(check.detail)}{duration} |"
            )
            lines.extend(f"  - Evidence: `{item}`" for item in check.evidence)
    else:
        lines.append("Runtime execution was not requested.")
    lines.extend(
        [
            "",
            "## Lifecycle results",
            "",
            f"- First run: `{report.first_run_result.value}`",
            f"- Fast path: `{report.fast_path_result.value}`",
            f"- Repair: `{report.repair_result.value}`",
            f"- Diagnostics: `{report.diagnostics_result.value}`",
            f"- Rollback: `{report.rollback_result.value}`",
            "",
            "## External runtimes",
            "",
        ]
    )
    if report.external_runtimes:
        for item in report.external_runtimes:
            lines.append(
                f"- **{item.name}**: `{item.status}`; feature "
                f"`{item.feature or 'core'}`. {item.detail}"
            )
    else:
        lines.append("No external runtime requirement applies to the selected deployment.")
    lines.extend(["", "## Manual GUI validation", ""])
    if report.manual_gui_checks:
        lines.extend(
            f"- [{'x' if item.status == 'pass' else ' '}] {item.instruction} (`{item.status}`)"
            for item in report.manual_gui_checks
        )
    else:
        lines.append("No manual GUI checks are required for this entry point.")
    if report.log_paths:
        lines.extend(["", "## Logs", ""])
        lines.extend(f"- `{item}`" for item in report.log_paths)
    lines.append("")
    return "\n".join(lines)
