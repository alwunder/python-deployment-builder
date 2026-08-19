"""Convert static observations into bounded deployment suitability findings."""

from __future__ import annotations

from python_deployment_builder.models import (
    ConfigurationRequirement,
    DependencyAssessment,
    FindingStatus,
    ImportObservation,
    PackagingAssessment,
    ResourceRequirement,
    RiskFinding,
    RiskSeverity,
    RuntimeRequirement,
    SuitabilityRating,
    WriteLocation,
)


def build_risks(
    project: PackagingAssessment,
    dependencies: list[DependencyAssessment],
    imports: list[ImportObservation],
    runtime: list[RuntimeRequirement],
    resources: list[ResourceRequirement],
    writes: list[WriteLocation],
    configuration: list[ConfigurationRequirement],
) -> list[RiskFinding]:
    risks: list[RiskFinding] = []
    if not project.lockfiles:
        risks.append(
            RiskFinding(
                code="DEPENDENCY_LOCK_MISSING",
                title="No supported dependency lockfile",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.DETECTED,
                description="End-user installation cannot yet use a frozen resolution.",
                recommendation=(
                    "Generate and review uv.lock during developer-side deployment preparation."
                ),
            )
        )
    if not project.entry_points:
        risks.append(
            RiskFinding(
                code="ENTRY_POINT_MISSING",
                title="No standardized application entry point",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.NEEDS_VALIDATION,
                description="The launcher target cannot be selected from standardized metadata.",
                recommendation=(
                    "Declare [project.scripts] or [project.gui-scripts], or configure an "
                    "explicit target."
                ),
            )
        )
    undeclared = [
        item for item in imports if item.classification == "observed_undeclared_third_party"
    ]
    if undeclared:
        risks.append(
            RiskFinding(
                code="UNDECLARED_IMPORTS",
                title="Observed imports are not matched to declared dependencies",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.INFERRED,
                description=(
                    "Static import names may represent undeclared dependencies or unknown "
                    "distribution/import mappings: "
                )
                + ", ".join(sorted({item.import_name for item in undeclared})),
                recommendation="Confirm the mapping and declare any true runtime dependency.",
                evidence=[evidence for item in undeclared for evidence in item.evidence[:2]],
            )
        )
    native = [item for item in dependencies if item.implementation == "native_or_compiled"]
    if native:
        risks.append(
            RiskFinding(
                code="NATIVE_WHEELS_UNVERIFIED",
                title="Native or compiled dependencies need Windows wheel verification",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.NEEDS_VALIDATION,
                description="Offline static analysis did not verify compatible Windows wheels for: "
                + ", ".join(item.distribution_name for item in native),
                recommendation=(
                    "Perform explicit online index assessment for the selected CPython minor "
                    "and architecture."
                ),
                evidence=[evidence for item in native for evidence in item.evidence[:1]],
            )
        )
    adjacent_used = [
        item
        for item in resources
        if item.packaging_status == "repository_adjacent" and len(item.evidence) > 1
    ]
    has_file_root = any(
        item.category == "path_assumption" and "__file__" in item.name for item in runtime
    )
    if adjacent_used and has_file_root:
        risks.append(
            RiskFinding(
                code="REPOSITORY_ADJACENT_RESOURCES",
                title="Runtime behavior depends on repository-adjacent resources",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.DETECTED,
                description=(
                    "A conventional detached wheel install may not preserve required files: "
                )
                + ", ".join(item.path for item in adjacent_used),
                recommendation=(
                    "Prefer source-based deployment initially or package resources deliberately "
                    "in the application."
                ),
                evidence=[evidence for item in adjacent_used for evidence in item.evidence[1:3]],
            )
        )
    project_writes = [item for item in writes if item.classification == "project_local"]
    if project_writes:
        risks.append(
            RiskFinding(
                code="PROJECT_LOCAL_WRITES",
                title="Application may write under the extracted repository",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.INFERRED,
                description=(
                    "No-admin deployment is viable only if the extracted project/output "
                    "locations are writable."
                ),
                recommendation=(
                    "Probe write access at startup and consider user-local defaults in the "
                    "application."
                ),
                evidence=[evidence for item in project_writes for evidence in item.evidence[:2]],
            )
        )
    secret_config = [item for item in configuration if item.secret]
    if secret_config:
        risks.append(
            RiskFinding(
                code="SECRET_CONFIGURATION",
                title="Secret-bearing configuration is used",
                severity=RiskSeverity.WARNING,
                status=FindingStatus.DETECTED,
                description=(
                    "Deployment must preserve configuration behavior without copying, embedding, "
                    "or logging values."
                ),
                recommendation=(
                    "Record names and presence only; never persist secret values in deployment "
                    "state."
                ),
                evidence=[evidence for item in secret_config for evidence in item.evidence[:2]],
            )
        )
    protected_writes = [
        item
        for item in writes
        if "program files" in item.path_expression.lower()
        or any(
            evidence.excerpt and "program files" in evidence.excerpt.lower()
            for evidence in item.evidence
        )
    ]
    if protected_writes:
        risks.append(
            RiskFinding(
                code="PROGRAM_FILES_WRITE_RISK",
                title="Potential write to a protected machine location",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.NEEDS_VALIDATION,
                description=(
                    "A detected Program Files reference may combine with a write path; elevation "
                    "is not an acceptable workaround."
                ),
                recommendation="Move runtime writes to per-user or user-selected locations.",
                evidence=[evidence for item in protected_writes for evidence in item.evidence],
            )
        )
    external_blockers = [
        item
        for item in runtime
        if item.category == "external_executable"
        and item.name.lower() in {"arcpy", "arcgispro.exe", "java", "java.exe", "nvidia-smi"}
    ]
    if external_blockers:
        risks.append(
            RiskFinding(
                code="REQUIRED_EXTERNAL_RUNTIME",
                title="Application appears to require an external runtime",
                severity=RiskSeverity.BLOCKING,
                status=FindingStatus.NEEDS_VALIDATION,
                description="Generic uv-managed CPython cannot supply: "
                + ", ".join(item.name for item in external_blockers),
                recommendation="Use a specialized backend or change the application requirement.",
                evidence=[evidence for item in external_blockers for evidence in item.evidence],
            )
        )
    return risks


def rate_suitability(risks: list[RiskFinding]) -> tuple[SuitabilityRating, str]:
    if any(risk.severity == RiskSeverity.BLOCKING for risk in risks):
        return (
            SuitabilityRating.RED,
            "Not suitable for automatic generic deployment until blocking application or "
            "external-runtime requirements are resolved.",
        )
    if any(risk.severity == RiskSeverity.WARNING for risk in risks):
        return (
            SuitabilityRating.YELLOW,
            "Likely deployable, but configuration, resource, write-location, lock, or runtime "
            "compatibility findings need attention.",
        )
    return (
        SuitabilityRating.GREEN,
        "Suitable for automated no-admin deployment based on static evidence.",
    )
