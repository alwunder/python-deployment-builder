"""Treat static multi-platform findings for the Windows deployment policy."""

from python_deployment_builder.models import PlatformFindingTreatment, RuntimeRequirement


def windows_finding_treatments(
    requirements: list[RuntimeRequirement],
) -> list[PlatformFindingTreatment]:
    results: list[PlatformFindingTreatment] = []
    for requirement in requirements:
        platforms = requirement.platforms
        if "windows" in platforms or "all" in platforms:
            decision = "applicable"
            rationale = "The finding can apply to the Windows deployment target."
        elif set(platforms) <= {"macos", "linux"}:
            decision = "ignored_for_windows"
            rationale = (
                "The finding is retained in assessment but excluded from "
                "Windows risk gating."
            )
        else:
            decision = "needs_validation"
            rationale = "Platform applicability is not statically certain."
        results.append(
            PlatformFindingTreatment(
                category=requirement.category,
                name=requirement.name,
                platforms=platforms,
                decision=decision,
                rationale=rationale,
            )
        )
    return results
