"""Stable persisted models shared by analysis, planning, and validation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from python_deployment_builder import (
    ANALYSIS_SCHEMA_VERSION,
    PLANNING_SCHEMA_VERSION,
    SCHEMA_VERSION,
)


class StrictModel(BaseModel):
    """Base model that rejects accidental schema drift inside the builder."""

    model_config = ConfigDict(extra="forbid")


class FindingStatus(StrEnum):
    DETECTED = "detected"
    INFERRED = "inferred"
    NEEDS_VALIDATION = "needs_validation"


class SuitabilityRating(StrEnum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class RiskSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    BLOCKING = "blocking"


class RepositoryFileRole(StrEnum):
    APPLICATION_SOURCE = "application_source"
    RUNTIME_RESOURCE = "runtime_resource"
    MUTABLE_STATE_CANDIDATE = "mutable_state_candidate"
    DEPLOYMENT_SUPPORT = "deployment_support"
    TEST = "test"
    DOCUMENTATION = "documentation"
    EXAMPLE_OR_SNIPPET = "example_or_snippet"
    DEVELOPMENT_TOOLING = "development_tooling"
    IGNORED_OR_LOCAL = "ignored_or_local"
    UNKNOWN = "unknown"


class GuidanceClassification(StrEnum):
    GOOD_PRACTICE = "good_practice"
    WORKS_BUT_IMPLICIT = "works_but_implicit"
    IMPROVEMENT_OPPORTUNITY = "improvement_opportunity"
    APPLICATION_SPECIFIC = "application_specific"
    PDB_LIMITATION = "pdb_limitation"
    GENERATION_BLOCKER = "generation_blocker"


class GuidancePriority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Evidence(StrictModel):
    file: str
    line: int | None = None
    detail: str
    excerpt: str | None = None


class RepositoryIdentity(StrictModel):
    source: str
    source_kind: Literal["local", "github_archive"]
    root_name: str
    revision: str | None = None
    fingerprint: str
    fingerprint_scope: Literal["deployment_inputs"] = "deployment_inputs"


class EntryPointAssessment(StrictModel):
    name: str
    target: str
    kind: Literal["cli", "gui", "unknown"]
    # This is the installed-wheel group declared by packaging metadata.  It
    # intentionally remains independent from PDB's launch/UI classification.
    declared_group: Literal["console_scripts", "gui_scripts", "unknown"] = "unknown"
    status: FindingStatus = FindingStatus.DETECTED
    evidence: list[Evidence] = Field(default_factory=list)


class EntryPointCandidate(StrictModel):
    path: str
    target: str | None = None
    kind: Literal["cli", "gui", "unknown"] = "unknown"
    confidence: Literal["high", "medium", "low"] = "medium"
    authoritative: bool = False
    evidence: list[Evidence] = Field(default_factory=list)


class LegacyDependencyGroup(StrictModel):
    name: str
    source_file: str
    distributions: list[str] = Field(default_factory=list)
    includes_groups: list[str] = Field(default_factory=list)
    aggregate_of: list[str] = Field(default_factory=list)
    authoritative_selectable_extra: bool = False
    evidence: list[Evidence] = Field(default_factory=list)


class RepositoryFileInventoryItem(StrictModel):
    path: str
    role: RepositoryFileRole
    included_in_runtime_scan: bool
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)


class AnalysisScopeSummary(StrictModel):
    application_source_files: int = 0
    runtime_resources: int = 0
    mutable_state_candidates: int = 0
    deployment_support_files: int = 0
    tests_excluded: int = 0
    documentation_excluded: int = 0
    examples_excluded: int = 0
    development_tooling_excluded: int = 0
    ignored_local_excluded: int = 0
    unknown_role_files: int = 0


class DeploymentSupportFinding(StrictModel):
    category: Literal[
        "launch_script",
        "repair_script",
        "diagnostic_script",
        "environment_provisioning",
        "registry_discovery",
        "runtime_management",
        "other",
    ]
    name: str
    description: str
    evidence: list[Evidence] = Field(default_factory=list)


class VendorRuntimeEvidence(StrictModel):
    name: str
    description: str
    backend_supported: bool = False
    required_for_core_launch: bool | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class StructuralGuidance(StrictModel):
    code: str
    classification: GuidanceClassification
    priority: GuidancePriority = GuidancePriority.MEDIUM
    title: str
    explanation: str
    why_it_matters: str
    suggested_direction: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class PackagingAssessment(StrictModel):
    metadata_files: list[str] = Field(default_factory=list)
    distribution_name: str | None = None
    version: str | None = None
    build_backend: str | None = None
    layout: Literal["src", "flat", "unknown"] = "unknown"
    source_roots: list[str] = Field(default_factory=list)
    packages: list[str] = Field(default_factory=list)
    py_modules: list[str] = Field(default_factory=list)
    package_directories: dict[str, str] = Field(default_factory=dict)
    package_data: dict[str, list[str]] = Field(default_factory=dict)
    exclude_package_data: dict[str, list[str]] = Field(default_factory=dict)
    package_data_evidence: dict[str, dict[str, Evidence]] = Field(default_factory=dict)
    exclude_package_data_evidence: dict[str, dict[str, Evidence]] = Field(default_factory=dict)
    entry_points: list[EntryPointAssessment] = Field(default_factory=list)
    optional_dependency_groups: dict[str, list[str]] = Field(default_factory=dict)
    legacy_dependency_groups: list[LegacyDependencyGroup] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)


class PythonRequirementAssessment(StrictModel):
    requires_python: str | None = None
    python_version_file: str | None = None
    ruff_target_version: str | None = None
    documented_versions: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.NEEDS_VALIDATION
    evidence: list[Evidence] = Field(default_factory=list)


class DependencyAssessment(StrictModel):
    distribution_name: str
    declared_constraint: str
    group: str = "runtime"
    environment_marker: str | None = None
    launch_critical: bool | None = None
    import_names: list[str] = Field(default_factory=list)
    implementation: Literal["pure_python", "native_or_compiled", "unknown"] = "unknown"
    windows_concern: Literal["low", "medium", "high", "unknown"] = "unknown"
    wheel_status: Literal["available", "unavailable", "not_assessed"] = "not_assessed"
    source_build_risk: Literal["low", "medium", "high", "unknown"] = "unknown"
    external_runtime_requirements: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.DETECTED
    evidence: list[Evidence] = Field(default_factory=list)


class ImportObservation(StrictModel):
    import_name: str
    classification: Literal[
        "standard_library",
        "local_project",
        "declared_third_party",
        "observed_undeclared_third_party",
    ]
    distribution_name: str | None = None
    optional_import: bool = False
    contexts: list[Literal["module_top_level", "deferred", "conditional", "type_checking"]] = Field(
        default_factory=lambda: ["module_top_level"]
    )
    evidence: list[Evidence] = Field(default_factory=list)


class RuntimeRequirement(StrictModel):
    category: str
    name: str
    description: str
    status: FindingStatus
    optional: bool | None = None
    platforms: list[Literal["windows", "macos", "linux", "all", "unknown"]] = Field(
        default_factory=lambda: ["all"]
    )
    evidence: list[Evidence] = Field(default_factory=list)


class ResourceRequirement(StrictModel):
    path: str
    kind: str
    access_mode: Literal["read", "write", "read_write", "unknown"] = "read"
    packaging_status: Literal["packaged", "repository_adjacent", "unknown"] = "unknown"
    status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)


class WriteLocation(StrictModel):
    path_expression: str
    classification: Literal[
        "project_local", "user_local", "temporary", "external_user_selected", "unknown"
    ]
    description: str
    status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)


class ConfigurationRequirement(StrictModel):
    name: str
    kind: Literal["environment_variable", "dotenv", "configuration_file", "unknown"]
    secret: bool = False
    required_at_launch: bool | None = None
    description: str
    status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)


class RiskFinding(StrictModel):
    code: str
    title: str
    severity: RiskSeverity
    status: FindingStatus
    description: str
    recommendation: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class RepositoryAssessment(StrictModel):
    schema_version: str = ANALYSIS_SCHEMA_VERSION
    generated_at: datetime
    tool_version: str
    repository: RepositoryIdentity
    project: PackagingAssessment
    file_inventory: list[RepositoryFileInventoryItem] = Field(default_factory=list)
    analysis_scope: AnalysisScopeSummary = Field(default_factory=AnalysisScopeSummary)
    entry_point_candidates: list[EntryPointCandidate] = Field(default_factory=list)
    deployment_support: list[DeploymentSupportFinding] = Field(default_factory=list)
    deployment_support_dependencies: list[DependencyAssessment] = Field(default_factory=list)
    vendor_runtimes: list[VendorRuntimeEvidence] = Field(default_factory=list)
    structural_guidance: list[StructuralGuidance] = Field(default_factory=list)
    python: PythonRequirementAssessment
    dependencies: list[DependencyAssessment] = Field(default_factory=list)
    imports: list[ImportObservation] = Field(default_factory=list)
    declared_but_apparently_unused: list[str] = Field(default_factory=list)
    runtime_requirements: list[RuntimeRequirement] = Field(default_factory=list)
    resources: list[ResourceRequirement] = Field(default_factory=list)
    write_locations: list[WriteLocation] = Field(default_factory=list)
    configuration_requirements: list[ConfigurationRequirement] = Field(default_factory=list)
    risks: list[RiskFinding] = Field(default_factory=list)
    rating: SuitabilityRating
    rating_summary: str
    analysis_limitations: list[str] = Field(default_factory=list)


class PlannedCommand(StrictModel):
    executable: str
    arguments: list[str] = Field(default_factory=list)
    working_directory: str | None = None
    purpose: str


class BootstrapArtifact(StrictModel):
    version: str
    architecture: Literal["x86_64", "arm64"]
    url: str
    sha256: str
    archive_member: str = "uv.exe"


class RuntimePaths(StrictModel):
    shared_root: str
    uv_executable: str
    python_install_root: str
    cache_root: str
    application_root: str
    environment_path: str
    logs_path: str
    state_path: str


class RuntimePlan(StrictModel):
    backend: Literal["uv_managed"]
    operating_system: Literal["windows"] = "windows"
    architecture: Literal["x86_64", "arm64"]
    python_version: str
    uv_version: str
    bootstrap_artifact: BootstrapArtifact
    paths: RuntimePaths
    environment_variables: dict[str, str] = Field(default_factory=dict)
    provision_command: PlannedCommand
    sync_command: PlannedCommand
    application_install_command: PlannedCommand | None = None
    launch_executable: str
    selected_extras: list[str] = Field(default_factory=list)


class PlanningDecision(StrictModel):
    topic: str
    selected: str
    rationale: str
    alternatives: list[str] = Field(default_factory=list)


class RiskGate(StrictModel):
    outcome: Literal["allow", "allow_with_warnings", "block"]
    blocking_codes: list[str] = Field(default_factory=list)
    warning_codes: list[str] = Field(default_factory=list)
    rationale: str


class EntrypointPlan(StrictModel):
    name: str
    target: str
    kind: Literal["cli", "gui", "unknown"]
    declared_group: Literal["console_scripts", "gui_scripts", "unknown"] = "unknown"
    module: str
    callable: str
    alternatives: list[str] = Field(default_factory=list)


class LockfilePlan(StrictModel):
    path: str = "uv.lock"
    status: Literal["present_unverified", "developer_generation_required"]
    developer_commands: list[PlannedCommand] = Field(default_factory=list)
    end_user_policy: Literal["locked"] = "locked"
    allow_end_user_update: bool = False


class ExtraDependencyPlan(StrictModel):
    distribution_name: str
    declared_constraint: str
    environment_marker: str | None = None
    platform_applicable: bool


class OptionalExtraPlan(StrictModel):
    name: str
    recommended: bool = False
    selected: bool = False
    dependencies: list[ExtraDependencyPlan] = Field(default_factory=list)
    recommendation_reason: str | None = None
    selection_reason: str


class DependencyEdge(StrictModel):
    from_package: str
    to_package: str
    marker: str | None = None
    applicable: bool = True
    selected_extra: str | None = None
    requested_dependency_extras: list[str] = Field(default_factory=list)
    activated_dependency_extra: str | None = None


class ArtifactAvailability(StrictModel):
    compatible_wheel_available: bool
    matching_wheels: list[str] = Field(default_factory=list)
    source_distribution_available: bool
    policy: Literal["wheel_usable", "developer_wheel_required", "no_artifact"]


class LockedDependency(StrictModel):
    name: str
    version: str
    direct: bool
    dependency_chain: list[str] = Field(default_factory=list)
    selected_extra: str | None = None
    requested_dependency_extras: list[str] = Field(default_factory=list)
    available_dependency_extras: list[str] = Field(default_factory=list)
    platform_relevance: Literal["applicable", "not_applicable", "unknown"] = "applicable"
    artifact: ArtifactAvailability


class ArtifactPolicyFinding(StrictModel):
    code: str
    package: str
    version: str
    status: Literal["developer_artifact_required", "unavailable"]
    dependency_chain: list[str] = Field(default_factory=list)
    selected_extra: str | None = None
    description: str


class DeploymentArtifactRequirement(StrictModel):
    package: str
    version: str
    action: Literal["developer_wheel_required"]
    reason: str
    wheelhouse_path: str = "deployment/wheels"


class LockGraphAssessment(StrictModel):
    inspected: bool
    python_version: str
    architecture: Literal["x86_64", "arm64"]
    selected_extras: list[str] = Field(default_factory=list)
    dependencies: list[LockedDependency] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    artifact_findings: list[ArtifactPolicyFinding] = Field(default_factory=list)
    artifact_requirements: list[DeploymentArtifactRequirement] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ExternalRuntimePlan(StrictModel):
    name: str
    platform: Literal["windows", "macos", "linux", "all", "unknown"]
    feature: str | None = None
    required_at_launch: bool
    required_for_feature: bool
    detection_strategy: str
    automatic_installation_policy: Literal["never_automatic", "manual_only"]
    status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)


class PlatformFindingTreatment(StrictModel):
    category: str
    name: str
    platforms: list[str]
    decision: Literal["applicable", "ignored_for_windows", "needs_validation"]
    rationale: str


class ShellPolicy(StrictModel):
    command_prompt_required: bool = True
    powershell_allowed: bool = False
    prohibited_executables: list[str] = Field(
        default_factory=lambda: ["powershell.exe", "pwsh.exe"]
    )


class BootstrapHostTool(StrictModel):
    executable: Literal["curl.exe", "tar.exe", "certutil.exe"]
    purpose: str
    must_preflight_execution: bool = True


class BootstrapModePlan(StrictModel):
    mode: Literal["online_cmd", "bundled_uv", "offline_bundle"]
    status: Literal["supported", "future"]
    requires_network: bool
    required_host_tools: list[BootstrapHostTool] = Field(default_factory=list)
    description: str


class BootstrapPlan(StrictModel):
    preferred_mode: Literal["bundled_uv", "online_cmd", "offline_bundle"]
    modes: list[BootstrapModePlan]
    powershell_allowed: bool = False
    tls_verification_required: bool = True
    allow_security_bypass: bool = False
    unavailable_policy: str


class DeploymentReadiness(StrictModel):
    state: Literal[
        "READY",
        "VALIDATION_REQUIRED",
        "BLOCKED_PENDING_LOCKFILE",
        "BLOCKED_PENDING_LOCK_VERIFICATION",
        "BLOCKED_PENDING_DEVELOPER_ARTIFACT",
        "BLOCKED_PENDING_APPLICATION_WHEEL",
        "BLOCKED_PENDING_ENTRYPOINT",
        "BLOCKED",
    ]
    blocker_codes: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)
    pending: list[str] = Field(default_factory=list)


class ConfigurationPlan(StrictModel):
    name: str
    secret: bool
    required_at_launch: bool | None = None
    supply_strategy: Literal[
        "existing_application_workflow", "environment", "configuration_file", "manual_review"
    ]
    persist_value: bool = False
    log_value: bool = False
    rationale: str


class WritePolicyPlan(StrictModel):
    requires_project_write_probe: bool = False
    project_local_locations: list[str] = Field(default_factory=list)
    failure_policy: str


class PythonCandidatePlan(StrictModel):
    version: str
    satisfies_requires_python: bool
    selected: bool = False
    compatibility: Literal["viable", "unverified", "incompatible"]
    rationale: str


class OnlineIndexContext(StrictModel):
    assessed_at: datetime
    index_name: str
    index_url: str
    python_targets: list[str]
    windows_architecture: Literal["x86_64", "arm64"]


class WheelCompatibility(StrictModel):
    distribution_name: str
    declared_constraint: str
    resolved_version: str | None = None
    python_version: str
    wheel_available: bool | None = None
    matching_wheels: list[str] = Field(default_factory=list)
    source_distribution_available: bool | None = None
    status: FindingStatus = FindingStatus.NEEDS_VALIDATION
    deployment_selection: Literal["selected", "informational_legacy_group"] = "selected"
    detail: str


class OnlineCompatibilityAssessment(StrictModel):
    context: OnlineIndexContext
    dependencies: list[WheelCompatibility] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DeploymentPlan(StrictModel):
    schema_version: str = PLANNING_SCHEMA_VERSION
    generated_at: datetime
    tool_version: str
    assessment_repository_fingerprint: str
    application_id: str
    application_display_name: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    deployment_mode_condition: Literal[
        "SOURCE_COMPATIBLE",
        "PACKAGE_PREFERRED",
        "ENTRYPOINT_REQUIRES_PACKAGE_MODE",
        "DEPLOYMENT_MODE_CONFLICT",
        "INSTALLED_PROJECT_REQUIRED",
    ] = "PACKAGE_PREFERRED"
    runtime: RuntimePlan
    entry_point: EntrypointPlan | None = None
    lockfile: LockfilePlan
    lock_graph: LockGraphAssessment | None = None
    risk_gate: RiskGate
    readiness: DeploymentReadiness
    extras: list[OptionalExtraPlan] = Field(default_factory=list)
    selected_extras_fingerprint: str
    external_runtimes: list[ExternalRuntimePlan] = Field(default_factory=list)
    vendor_runtimes: list[VendorRuntimeEvidence] = Field(default_factory=list)
    platform_findings: list[PlatformFindingTreatment] = Field(default_factory=list)
    shell_policy: ShellPolicy
    bootstrap: BootstrapPlan
    python_candidates: list[PythonCandidatePlan] = Field(default_factory=list)
    configuration: list[ConfigurationPlan] = Field(default_factory=list)
    writes: WritePolicyPlan
    decisions: list[PlanningDecision] = Field(default_factory=list)
    online_compatibility: OnlineCompatibilityAssessment | None = None
    validation_requirements: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    structural_guidance: list[StructuralGuidance] = Field(default_factory=list)
    application_version: str | None = None
    repository_revision: str | None = None


class ApprovedArtifact(StrictModel):
    distribution_name: str
    version: str
    filename: str
    sha256: str
    wheel_tags: list[str] = Field(default_factory=list)
    requirement_action: Literal["developer_wheel_required"] = "developer_wheel_required"


class ApplicationArtifact(StrictModel):
    distribution_name: str
    version: str
    filename: str
    sha256: str
    wheel_tags: list[str] = Field(default_factory=list)
    entry_point_name: str
    entry_point_target: str
    # Required for unreleased M6.1 package mode; never inferred from wheel contents.
    authoritative_members: list[str] = Field(min_length=1)


class DeploymentManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    builder_version: str
    generated_at: datetime
    generation_id: str
    application_id: str
    application_display_name: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    entry_point_name: str
    entry_point_kind: Literal["cli", "gui", "unknown"]
    entry_point_module: str
    entry_point_callable: str
    python_version: str
    architecture: Literal["x86_64", "arm64"]
    uv_version: str
    uv_archive_url: str
    uv_archive_sha256: str
    bundled_uv_sha256: str | None = None
    bootstrap_mode: Literal["bundled_uv", "online_cmd"]
    system_certs: bool = False
    selected_extras: list[str] = Field(default_factory=list)
    selected_extras_fingerprint: str
    source_roots: list[str] = Field(default_factory=list)
    project_working_directory: str = "."
    pyproject_sha256: str
    lockfile_sha256: str
    assessment_repository_fingerprint: str
    deployment_fingerprint: str
    approved_artifacts: list[ApprovedArtifact] = Field(default_factory=list)
    application_artifact: ApplicationArtifact | None = None
    external_runtimes: list[ExternalRuntimePlan] = Field(default_factory=list)
    runtime_paths: RuntimePaths
    runtime_environment: dict[str, str] = Field(default_factory=dict)
    sync_arguments: list[str] = Field(default_factory=list)
    project_write_probe_required: bool = False
    configuration_presence_names: list[str] = Field(default_factory=list)
    configuration_secret_names: list[str] = Field(default_factory=list)
    referenced_files: list[str] = Field(default_factory=list)
    application_version: str | None = None
    runtime_backend: Literal["uv_managed"] = "uv_managed"
    source_revision: str | None = None


class GeneratedArtifact(StrictModel):
    path: str
    purpose: str
    sha256: str


class GenerationPreview(StrictModel):
    application_id: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    output_directory: str
    dry_run: bool
    readiness_before: str
    readiness_after: str | None = None
    source_roots: list[str] = Field(default_factory=list)
    bootstrap_mode: Literal["bundled_uv", "online_cmd"]
    system_certs: bool = False
    developer_actions: list[str] = Field(default_factory=list)
    application_wheel_required: bool = False
    application_artifact: ApplicationArtifact | None = None
    repository_files_changed: list[str] = Field(default_factory=list)
    files_to_create: list[str] = Field(default_factory=list)
    files_to_replace: list[str] = Field(default_factory=list)
    collisions: list[str] = Field(default_factory=list)
    runtime_paths: RuntimePaths
    launcher_behavior: list[str] = Field(default_factory=list)


class GenerationResult(StrictModel):
    output_directory: str
    dry_run: bool
    generated: bool
    manifest: DeploymentManifest | None = None
    preview: GenerationPreview
    artifacts: list[GeneratedArtifact] = Field(default_factory=list)
    structural_checks: list[RiskFinding] = Field(default_factory=list)


class ValidationResult(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    level: Literal["static", "runtime"]
    passed: bool
    checks: list[RiskFinding] = Field(default_factory=list)


class ValidationCheckStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    PLANNED = "PLANNED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"


class ValidationFinalState(StrEnum):
    STATIC_VALID = "STATIC_VALID"
    RUNTIME_VALIDATED = "RUNTIME_VALIDATED"
    MANUAL_GUI_VALIDATION_REQUIRED = "MANUAL_GUI_VALIDATION_REQUIRED"
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"


class ValidationCheckResult(StrictModel):
    code: str
    phase: Literal[
        "static",
        "first_run",
        "fast_path",
        "staleness",
        "rollback",
        "repair",
        "diagnostics",
        "external_runtime",
        "manual",
    ]
    status: ValidationCheckStatus
    detail: str
    evidence: list[str] = Field(default_factory=list)
    duration_seconds: float | None = None


class ValidationHost(StrictModel):
    operating_system: str
    windows_version: str | None = None
    architecture: str
    hostname: str
    username: str


class ExternalRuntimeValidation(StrictModel):
    name: str
    feature: str | None = None
    status: Literal["installed", "not_detected", "not_checked", "not_applicable"]
    version: str | None = None
    detail: str


class ManualValidationItem(StrictModel):
    instruction: str
    status: Literal["required", "pass", "fail"] = "required"


class ValidationReport(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    application_id: str
    application_display_name: str
    deployment_fingerprint: str
    kit_root: str
    validation_mode: Literal["static", "runtime"]
    dry_run: bool = False
    host: ValidationHost
    static_checks: list[ValidationCheckResult] = Field(default_factory=list)
    runtime_checks: list[ValidationCheckResult] = Field(default_factory=list)
    external_runtimes: list[ExternalRuntimeValidation] = Field(default_factory=list)
    manual_gui_checks: list[ManualValidationItem] = Field(default_factory=list)
    log_paths: list[str] = Field(default_factory=list)
    runtime_root: str | None = None
    first_run_result: ValidationCheckStatus = ValidationCheckStatus.SKIPPED
    fast_path_result: ValidationCheckStatus = ValidationCheckStatus.SKIPPED
    repair_result: ValidationCheckStatus = ValidationCheckStatus.SKIPPED
    diagnostics_result: ValidationCheckStatus = ValidationCheckStatus.SKIPPED
    rollback_result: ValidationCheckStatus = ValidationCheckStatus.SKIPPED
    final_state: ValidationFinalState


class ReleasePackageState(StrEnum):
    READY_FOR_MANUAL_ACCEPTANCE = "READY_FOR_MANUAL_ACCEPTANCE"


class ReleaseManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    application_id: str
    application_display_name: str
    application_version: str
    package_platform: Literal["windows"] = "windows"
    architecture: Literal["x86_64", "arm64"]
    builder_version: str
    deployment_fingerprint: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    runtime_backend: Literal["uv_managed"]
    python_version: str
    python_policy: Literal["managed"] = "managed"
    uv_version: str
    bootstrap_mode: Literal["bundled_uv", "online_cmd"]
    system_certs: bool
    selected_extras: list[str] = Field(default_factory=list)
    pyproject_sha256: str
    lockfile_sha256: str
    approved_artifacts: list[ApprovedArtifact] = Field(default_factory=list)
    application_artifact: ApplicationArtifact | None = None
    external_runtimes: list[ExternalRuntimePlan] = Field(default_factory=list)
    source_revision: str | None = None
    assessment_repository_fingerprint: str
    zip_filename: str
    zip_byte_size: int
    zip_sha256: str
    static_validation_state: Literal["STATIC_VALID"] = "STATIC_VALID"
    extracted_zip_validation_state: Literal["STATIC_VALID"] = "STATIC_VALID"
    manual_acceptance_required: bool = True
    final_state: ReleasePackageState = ReleasePackageState.READY_FOR_MANUAL_ACCEPTANCE


class PackagePreview(StrictModel):
    kit_root: str
    output_directory: str
    application_id: str
    application_display_name: str
    application_version: str
    application_slug: str
    zip_filename: str
    checksum_filename: str
    files_to_package: list[str] = Field(default_factory=list)
    release_manifest_fields: list[str] = Field(default_factory=list)
    static_validation_state: str
    dry_run: bool


class PackageResult(StrictModel):
    generated: bool
    dry_run: bool
    state: ReleasePackageState
    preview: PackagePreview
    manifest: ReleaseManifest | None = None
    zip_path: str | None = None
    checksum_path: str | None = None
    manifest_json_path: str | None = None
    manifest_markdown_path: str | None = None
    smoke_test_path: str | None = None
