"""Extensible package/framework to non-Python runtime rules."""

from __future__ import annotations

from dataclasses import dataclass

from packaging.utils import canonicalize_name

from python_deployment_builder.models import (
    DependencyAssessment,
    ExternalRuntimePlan,
    FindingStatus,
)


@dataclass(frozen=True)
class ExternalRuntimeRule:
    distribution: str
    name: str
    platform: str
    detection_strategy: str


RULES = (
    ExternalRuntimeRule(
        distribution="pywebview",
        name="Microsoft Edge WebView2 Runtime",
        platform="windows",
        detection_strategy=(
            "Preflight the pywebview EdgeChromium backend and report WebView2 availability; do "
            "not launch the long-running GUI during unattended validation."
        ),
    ),
)


def external_runtime_requirements(
    dependencies: list[DependencyAssessment], selected_extras: list[str]
) -> list[ExternalRuntimePlan]:
    selected_extra_names = {canonicalize_name(name) for name in selected_extras}
    by_name = {canonicalize_name(item.distribution_name): item for item in dependencies}
    results: list[ExternalRuntimePlan] = []
    for rule in RULES:
        dependency = by_name.get(canonicalize_name(rule.distribution))
        if dependency is None:
            continue
        feature = (
            dependency.group
            if canonicalize_name(dependency.group) in selected_extra_names
            else None
        )
        results.append(
            ExternalRuntimePlan(
                name=rule.name,
                platform=rule.platform,
                feature=feature,
                required_at_launch=dependency.group == "runtime",
                required_for_feature=feature is not None,
                detection_strategy=rule.detection_strategy,
                automatic_installation_policy="never_automatic",
                status=FindingStatus.NEEDS_VALIDATION,
                evidence=dependency.evidence,
            )
        )
    return results
