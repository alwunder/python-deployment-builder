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


class RuntimePlan(StrictModel):
    backend: str
    python_version: str
    runtime_root: str
    environment_path: str
    uv_version: str | None = None


class DeploymentPlan(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    application_id: str
    deployment_mode: Literal["source", "package", "source_resource_copy"]
    runtime: RuntimePlan
    decisions: list[str] = Field(default_factory=list)


class GeneratedArtifact(StrictModel):
    path: str
    purpose: str
    sha256: str


class ValidationResult(StrictModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    level: Literal["static", "runtime"]
    passed: bool
    checks: list[RiskFinding] = Field(default_factory=list)
