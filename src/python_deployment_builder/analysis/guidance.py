"""Evidence-backed structural guidance derived from assessment facts."""

from __future__ import annotations

from python_deployment_builder.models import (
    DeploymentSupportFinding,
    EntryPointCandidate,
    Evidence,
    GuidanceClassification,
    GuidancePriority,
    PackagingAssessment,
    ResourceRequirement,
    StructuralGuidance,
    VendorRuntimeEvidence,
    WriteLocation,
)


def build_structural_guidance(
    project: PackagingAssessment,
    candidates: list[EntryPointCandidate],
    resources: list[ResourceRequirement],
    writes: list[WriteLocation],
    deployment_support: list[DeploymentSupportFinding],
    vendor_runtimes: list[VendorRuntimeEvidence],
    ignored_runtime_resources: list[ResourceRequirement],
) -> list[StructuralGuidance]:
    guidance: list[StructuralGuidance] = []
    standardized_metadata = any(
        path in project.metadata_files for path in ("pyproject.toml", "setup.cfg", "setup.py")
    )
    if standardized_metadata:
        guidance.append(
            StructuralGuidance(
                code="STANDARDIZED_METADATA_PRESENT",
                classification=GuidanceClassification.GOOD_PRACTICE,
                priority=GuidancePriority.LOW,
                title="Standardized project metadata is present",
                explanation="PDB can use declared project identity and dependency evidence.",
                why_it_matters=(
                    "Explicit metadata makes deployment decisions reviewable and repeatable."
                ),
                evidence=[
                    Evidence(
                        file=next(
                            path
                            for path in project.metadata_files
                            if path in {"pyproject.toml", "setup.cfg", "setup.py"}
                        ),
                        detail="Supported standardized project metadata was detected.",
                    )
                ],
            )
        )
    else:
        guidance.append(
            StructuralGuidance(
                code="STANDARDIZED_METADATA_RECOMMENDED",
                classification=GuidanceClassification.IMPROVEMENT_OPPORTUNITY,
                priority=GuidancePriority.HIGH,
                title="Project metadata is implicit",
                explanation=(
                    "The repository relies on legacy dependency files or source/documentation "
                    "evidence "
                    "instead of standardized project metadata."
                ),
                why_it_matters=(
                    "Application identity, version, Python compatibility, dependencies, and "
                    "entry points "
                    "cannot all be established authoritatively."
                ),
                suggested_direction=(
                    "Consider adding reviewed pyproject.toml metadata when the application is "
                    "ready for modernization."
                ),
                evidence=[
                    Evidence(
                        file="repository",
                        detail="No supported standardized project metadata was detected.",
                    )
                ],
            )
        )
    if project.entry_points:
        guidance.append(
            StructuralGuidance(
                code="AUTHORITATIVE_ENTRYPOINT_DECLARED",
                classification=GuidanceClassification.GOOD_PRACTICE,
                priority=GuidancePriority.LOW,
                title="Authoritative application entry point is declared",
                explanation="Standardized metadata identifies the callable used for deployment.",
                why_it_matters=(
                    "PDB does not need to guess which script represents the product launcher."
                ),
                evidence=[evidence for item in project.entry_points for evidence in item.evidence],
            )
        )
        declared_targets = {item.target for item in project.entry_points}
        candidate_targets = {item.target for item in candidates if item.target}
        if candidate_targets and declared_targets.isdisjoint(candidate_targets):
            guidance.append(
                StructuralGuidance(
                    code="ENTRYPOINT_CANDIDATE_DISAGREES_WITH_METADATA",
                    classification=GuidanceClassification.IMPROVEMENT_OPPORTUNITY,
                    priority=GuidancePriority.MEDIUM,
                    title="Launcher candidates differ from declared entry points",
                    explanation=(
                        "Static launcher candidates do not invoke any callable declared in "
                        "standardized entry-point metadata. Metadata remains authoritative."
                    ),
                    why_it_matters=(
                        "Documentation or legacy launch scripts may describe a different product "
                        "path than the deployable entry point."
                    ),
                    suggested_direction=(
                        "Review the discrepancy and align or document the launch paths "
                        "deliberately."
                    ),
                    evidence=[evidence for item in candidates for evidence in item.evidence[:1]],
                )
            )
    else:
        candidate_text = (
            f" A likely candidate is {candidates[0].path} -> {candidates[0].target}."
            if candidates
            else " No high-confidence launcher candidate was found."
        )
        guidance.append(
            StructuralGuidance(
                code="ENTRYPOINT_DECLARATION_REQUIRED",
                classification=GuidanceClassification.GENERATION_BLOCKER,
                priority=GuidancePriority.HIGH,
                title="An authoritative entry point is required",
                explanation=(
                    "PDB will not promote a heuristic launcher candidate into a deployment "
                    "contract." + candidate_text
                ),
                why_it_matters=(
                    "Launching the wrong callable can execute unintended code or create a broken "
                    "kit."
                ),
                suggested_direction=(
                    "Declare [project.gui-scripts] or [project.scripts] in standardized metadata."
                ),
                evidence=(
                    candidates[0].evidence
                    if candidates
                    else [
                        Evidence(
                            file="repository",
                            detail=(
                                "No authoritative entry point or diagnostic candidate was "
                                "detected."
                            ),
                        )
                    ]
                ),
            )
        )
    legacy_groups = [item.name for item in project.legacy_dependency_groups]
    if legacy_groups:
        guidance.append(
            StructuralGuidance(
                code="LEGACY_REQUIREMENTS_GROUPS_IMPLICIT",
                classification=GuidanceClassification.WORKS_BUT_IMPLICIT,
                priority=GuidancePriority.MEDIUM,
                title="Requirements-file feature groups are implicit",
                explanation=(
                    "PDB can analyze legacy groups "
                    + ", ".join(sorted(legacy_groups))
                    + ", but does not treat them as authoritative selectable extras."
                ),
                why_it_matters=(
                    "Filenames alone do not define core, optional, aggregate, or development "
                    "semantics."
                ),
                suggested_direction=(
                    "Consider moving core requirements to [project].dependencies and selectable "
                    "capabilities to "
                    "[project.optional-dependencies] when modernizing metadata."
                ),
                evidence=[
                    Evidence(
                        file=item.source_file,
                        detail=f"Legacy dependency group {item.name!r} is declared here.",
                    )
                    for item in project.legacy_dependency_groups
                ],
            )
        )
        aggregates = [
            f"{item.name} -> {', '.join(item.aggregate_of)}"
            for item in project.legacy_dependency_groups
            if item.aggregate_of
        ]
        if aggregates:
            guidance.append(
                StructuralGuidance(
                    code="LEGACY_REQUIREMENTS_AGGREGATE_DETECTED",
                    classification=GuidanceClassification.WORKS_BUT_IMPLICIT,
                    priority=GuidancePriority.LOW,
                    title="Requirements-file aggregate relationships were detected",
                    explanation=(
                        "Explicit includes or strict dependency supersets suggest: "
                        + "; ".join(aggregates)
                        + ". This is descriptive, not selectable-extra authority."
                    ),
                    why_it_matters=(
                        "PDB can explain overlap without guessing that filenames define features."
                    ),
                    evidence=[
                        Evidence(
                            file=item.source_file,
                            detail=(
                                f"Group {item.name!r} includes or is a strict superset of "
                                f"{', '.join(item.aggregate_of)}."
                            ),
                        )
                        for item in project.legacy_dependency_groups
                        if item.aggregate_of
                    ],
                )
            )
    if not project.lockfiles:
        guidance.append(
            StructuralGuidance(
                code="REPRODUCIBLE_LOCK_REQUIRED",
                classification=GuidanceClassification.GENERATION_BLOCKER,
                priority=GuidancePriority.HIGH,
                title="A verified deployment lockfile is required",
                explanation="No supported lockfile records an end-user dependency resolution.",
                why_it_matters=(
                    "A release cannot use PDB's locked/no-build synchronization policy without it."
                ),
                suggested_direction=(
                    "Create and review uv.lock during an explicit developer-preparation workflow."
                ),
                evidence=[
                    Evidence(file="repository", detail="No supported deployment lockfile exists.")
                ],
            )
        )
    project_writes = [item for item in writes if item.classification == "project_local"]
    if project_writes:
        guidance.append(
            StructuralGuidance(
                code="SOURCE_ADJACENT_MUTABLE_STATE",
                classification=GuidanceClassification.IMPROVEMENT_OPPORTUNITY,
                priority=GuidancePriority.MEDIUM,
                title="Mutable state may be stored beside application source",
                explanation=(
                    "This can work in a writable extracted repository, but couples persistent "
                    "user data "
                    "to the source/distribution tree."
                ),
                why_it_matters=(
                    "Read-only installs, upgrades, and multi-user use become harder to reason "
                    "about."
                ),
                suggested_direction="Consider a per-user state directory such as LocalAppData.",
                evidence=[evidence for item in project_writes for evidence in item.evidence[:2]],
            )
        )
    if deployment_support:
        guidance.append(
            StructuralGuidance(
                code="EXISTING_DEPLOYMENT_ARCHITECTURE",
                classification=GuidanceClassification.APPLICATION_SPECIFIC,
                priority=GuidancePriority.MEDIUM,
                title="Existing deployment architecture was detected",
                explanation=(
                    "Launch, repair, diagnostics, or environment-management files are inventoried "
                    "separately from application runtime source."
                ),
                why_it_matters=(
                    "PDB should describe potential integration/collision points without adopting "
                    "them implicitly."
                ),
                evidence=[
                    evidence for item in deployment_support for evidence in item.evidence[:1]
                ],
            )
        )
    for vendor in vendor_runtimes:
        if vendor.backend_supported:
            guidance.append(
                StructuralGuidance(
                    code="EXTERNAL_RUNTIME_EVIDENCE",
                    classification=GuidanceClassification.APPLICATION_SPECIFIC,
                    priority=GuidancePriority.MEDIUM,
                    title=f"{vendor.name} external runtime evidence",
                    explanation=vendor.description,
                    why_it_matters=(
                        "Feature-specific external runtimes should be detected and validated "
                        "without being silently installed."
                    ),
                    evidence=vendor.evidence,
                )
            )
            continue
        guidance.append(
            StructuralGuidance(
                code="VENDOR_RUNTIME_BACKEND_UNSUPPORTED",
                classification=GuidanceClassification.PDB_LIMITATION,
                priority=GuidancePriority.HIGH,
                title=f"{vendor.name} vendor runtime has no PDB backend",
                explanation=vendor.description,
                why_it_matters=(
                    "A managed-CPython plan cannot be assumed equivalent to a vendor-provided "
                    "runtime."
                ),
                suggested_direction=(
                    "Keep vendor-backed features explicit and evaluate a dedicated backend only "
                    "after "
                    "their runtime contract is understood."
                ),
                evidence=vendor.evidence,
            )
        )
    for resource in ignored_runtime_resources:
        guidance.append(
            StructuralGuidance(
                code="RUNTIME_DEPENDENCY_IS_IGNORED",
                classification=GuidanceClassification.GENERATION_BLOCKER,
                priority=GuidancePriority.HIGH,
                title="Referenced runtime resource is ignored",
                explanation=(
                    f"Application source references {resource.path}, but repository ignore rules "
                    "exclude it."
                ),
                why_it_matters=(
                    "A clean checkout or staged distribution may omit a file the application reads."
                ),
                suggested_direction=(
                    "Track/package the resource or remove the runtime dependency deliberately."
                ),
                evidence=resource.evidence,
            )
        )
    return guidance
