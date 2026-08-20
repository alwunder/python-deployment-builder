"""Optional feature selection kept separate from static detection."""

from __future__ import annotations

from packaging.utils import canonicalize_name

from python_deployment_builder.models import (
    DependencyAssessment,
    ExtraDependencyPlan,
    OptionalExtraPlan,
    RepositoryAssessment,
)
from python_deployment_builder.planning.index import marker_applies


def validate_selected_extras(
    assessment: RepositoryAssessment, selected_extras: list[str]
) -> list[str]:
    available = set(assessment.project.optional_dependency_groups)
    selected = list(dict.fromkeys(selected_extras))
    unknown = sorted(set(selected) - available)
    if unknown:
        raise ValueError(
            "Unknown optional dependency extra(s): "
            + ", ".join(unknown)
            + ". Available extras: "
            + (", ".join(sorted(available)) or "none")
        )
    return selected


def selected_dependencies(
    assessment: RepositoryAssessment,
    selected_extras: list[str],
    python_version: str,
    architecture: str,
) -> list[DependencyAssessment]:
    dependencies: list[DependencyAssessment] = []
    for dependency in assessment.dependencies:
        if dependency.group == "runtime" or dependency.group in selected_extras:
            extra = dependency.group if dependency.group != "runtime" else ""
            if marker_applies(
                dependency.environment_marker,
                python_version,
                architecture,
                extra=extra,
            ):
                dependencies.append(dependency)
    return dependencies


def _recommended_groups(assessment: RepositoryAssessment) -> dict[str, str]:
    imported_distributions = {
        canonicalize_name(item.distribution_name)
        for item in assessment.imports
        if item.distribution_name
    }
    recommended: dict[str, str] = {}
    for dependency in assessment.dependencies:
        if dependency.group in {"runtime", "dev"}:
            continue
        if canonicalize_name(dependency.distribution_name) in imported_distributions:
            recommended[dependency.group] = (
                f"Application source references {dependency.distribution_name}, which is supplied "
                f"by the optional '{dependency.group}' feature."
            )
    return recommended


def build_extra_plans(
    assessment: RepositoryAssessment,
    selected_extras: list[str],
    python_version: str,
    architecture: str,
) -> list[OptionalExtraPlan]:
    recommended = _recommended_groups(assessment)
    plans: list[OptionalExtraPlan] = []
    for name in assessment.project.optional_dependency_groups:
        selected = name in selected_extras
        dependencies = [
            ExtraDependencyPlan(
                distribution_name=item.distribution_name,
                declared_constraint=item.declared_constraint,
                environment_marker=item.environment_marker,
                platform_applicable=marker_applies(
                    item.environment_marker,
                    python_version,
                    architecture,
                    extra=name,
                ),
            )
            for item in assessment.dependencies
            if item.group == name
        ]
        plans.append(
            OptionalExtraPlan(
                name=name,
                recommended=name in recommended,
                selected=selected,
                dependencies=dependencies,
                recommendation_reason=recommended.get(name),
                selection_reason=(
                    "Explicitly selected by the deployment developer."
                    if selected
                    else (
                        "Excluded by default; optional extras require explicit "
                        "deployment selection."
                    )
                ),
            )
        )
    return plans
