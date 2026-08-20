"""Stable persisted models shared by analysis, planning, and validation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from python_deployment_builder import SCHEMA_VERSION


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


class EntryPointAssessment(StrictModel):
    name: str
    target: str
    kind: Literal["cli", "gui", "unknown"]
    status: FindingStatus = FindingStatus.DETECTED
    evidence: list[Evidence] = Field(default_factory=list)


class PackagingAssessment(StrictModel):
    metadata_files: list[str] = Field(default_factory=list)
    distribution_name: str | None = None
    version: str | None = None
    build_backend: str | None = None
    layout: Literal["src", "flat", "unknown"] = "unknown"
    source_roots: list[str] = Field(default_factory=list)
    entry_points: list[EntryPointAssessment] = Field(default_factory=list)
    optional_dependency_groups: dict[str, list[str]] = Field(default_factory=dict)
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
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    tool_version: str
    repository: RepositoryIdentity
    project: PackagingAssessment
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
        "BLOCKED",
    ]
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
    detail: str


class OnlineCompatibilityAssessment(StrictModel):
    context: OnlineIndexContext
    dependencies: list[WheelCompatibility] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DeploymentPlan(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    tool_version: str
    assessment_repository_fingerprint: str
    application_id: str
    application_display_name: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    runtime: RuntimePlan
    entry_point: EntrypointPlan
    lockfile: LockfilePlan
    lock_graph: LockGraphAssessment | None = None
    risk_gate: RiskGate
    readiness: DeploymentReadiness
    extras: list[OptionalExtraPlan] = Field(default_factory=list)
    selected_extras_fingerprint: str
    external_runtimes: list[ExternalRuntimePlan] = Field(default_factory=list)
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


class ApprovedArtifact(StrictModel):
    distribution_name: str
    version: str
    filename: str
    sha256: str
    wheel_tags: list[str] = Field(default_factory=list)
    requirement_action: Literal["developer_wheel_required"] = "developer_wheel_required"


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
    external_runtimes: list[ExternalRuntimePlan] = Field(default_factory=list)
    runtime_paths: RuntimePaths
    runtime_environment: dict[str, str] = Field(default_factory=dict)
    sync_arguments: list[str] = Field(default_factory=list)
    project_write_probe_required: bool = False
    configuration_presence_names: list[str] = Field(default_factory=list)
    referenced_files: list[str] = Field(default_factory=list)


class GeneratedArtifact(StrictModel):
    path: str
    purpose: str
    sha256: str


class GenerationPreview(StrictModel):
    application_id: str
    output_directory: str
    dry_run: bool
    readiness_before: str
    readiness_after: str | None = None
    bootstrap_mode: Literal["bundled_uv", "online_cmd"]
    system_certs: bool = False
    developer_actions: list[str] = Field(default_factory=list)
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
