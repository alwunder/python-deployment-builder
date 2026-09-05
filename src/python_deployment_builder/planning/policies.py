"""Explicit, testable choices made independently of repository analysis."""

from __future__ import annotations

import re
from enum import StrEnum

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from python_deployment_builder.models import RepositoryAssessment

PYTHON_POLICY_ORDER = ("3.12", "3.13", "3.11", "3.14")


class MinorPythonCompatibility(StrEnum):
    """Whether a requirement is provable for a minor-only managed runtime."""

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNPROVABLE = "unprovable"


def safe_application_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized[:64] or "python-application"


def _minor_bounds(version: str) -> tuple[Version, Version]:
    """Return the closed/open patch interval represented by a Python minor."""

    match = re.fullmatch(r"(\d+)\.(\d+)", version)
    if match is None:
        raise ValueError(f"Python policy version must be major.minor: {version!r}")
    major, minor = (int(value) for value in match.groups())
    return Version(f"{major}.{minor}.0"), Version(f"{major}.{minor + 1}.0")


def _combine_minor_results(
    values: list[MinorPythonCompatibility],
) -> MinorPythonCompatibility:
    if MinorPythonCompatibility.INCOMPATIBLE in values:
        return MinorPythonCompatibility.INCOMPATIBLE
    if MinorPythonCompatibility.UNPROVABLE in values:
        return MinorPythonCompatibility.UNPROVABLE
    return MinorPythonCompatibility.COMPATIBLE


def _range_result(
    operator: str, boundary: Version, low: Version, high: Version
) -> MinorPythonCompatibility:
    """Classify a simple ordered comparison over every possible patch release."""

    if operator == ">=":
        return (
            MinorPythonCompatibility.COMPATIBLE
            if boundary <= low
            else MinorPythonCompatibility.INCOMPATIBLE
            if boundary >= high
            else MinorPythonCompatibility.UNPROVABLE
        )
    if operator == ">":
        return (
            MinorPythonCompatibility.COMPATIBLE
            if boundary < low
            else MinorPythonCompatibility.INCOMPATIBLE
            if boundary >= high
            else MinorPythonCompatibility.UNPROVABLE
        )
    if operator == "<":
        return (
            MinorPythonCompatibility.COMPATIBLE
            if boundary >= high
            else MinorPythonCompatibility.INCOMPATIBLE
            if boundary <= low
            else MinorPythonCompatibility.UNPROVABLE
        )
    if operator == "<=":
        return (
            MinorPythonCompatibility.COMPATIBLE
            if boundary >= high
            else MinorPythonCompatibility.INCOMPATIBLE
            if boundary < low
            else MinorPythonCompatibility.UNPROVABLE
        )
    raise ValueError(f"Unsupported range operator: {operator}")


def _wildcard_result(
    operator: str, raw_version: str, version: str
) -> MinorPythonCompatibility:
    prefix = raw_version.removesuffix(".*").split(".")
    minor_parts = version.split(".")
    matches = minor_parts[: len(prefix)] == prefix
    if operator == "==":
        return (
            MinorPythonCompatibility.COMPATIBLE
            if matches
            else MinorPythonCompatibility.INCOMPATIBLE
        )
    if operator == "!=":
        return (
            MinorPythonCompatibility.INCOMPATIBLE
            if matches
            else MinorPythonCompatibility.COMPATIBLE
        )
    return MinorPythonCompatibility.UNPROVABLE


def _compatible_upper_bound(version: Version) -> Version | None:
    """Return the PEP 440 compatible-release upper bound for a plain release."""

    if version.pre or version.post is not None or version.dev is not None or version.local:
        return None
    release = version.release
    if len(release) < 2:
        return None
    prefix = list(release[:-1])
    prefix[-1] += 1
    return Version(".".join(str(value) for value in prefix))


def minor_python_compatibility(
    version: str, requires_python: str | None
) -> MinorPythonCompatibility:
    """Evaluate a Python specifier without pretending a selected minor has patch ``.0``.

    PDB provisions a major/minor runtime.  A result is compatible only when
    every possible patch release of that minor satisfies the requirement;
    incompatible only when none can satisfy it.  All other forms are kept
    deliberately unprovable.
    """

    if not requires_python:
        return MinorPythonCompatibility.COMPATIBLE
    low, high = _minor_bounds(version)
    specifiers = SpecifierSet(requires_python)
    results: list[MinorPythonCompatibility] = []
    for specifier in specifiers:
        operator = specifier.operator
        raw = specifier.version
        if raw.endswith(".*"):
            results.append(_wildcard_result(operator, raw, version))
            continue
        try:
            boundary = Version(raw)
        except InvalidVersion:
            results.append(MinorPythonCompatibility.UNPROVABLE)
            continue
        if operator in {">=", ">", "<", "<="}:
            results.append(_range_result(operator, boundary, low, high))
        elif operator == "~=":
            upper = _compatible_upper_bound(boundary)
            results.append(
                MinorPythonCompatibility.UNPROVABLE
                if upper is None
                else _combine_minor_results(
                    [
                        _range_result(">=", boundary, low, high),
                        _range_result("<", upper, low, high),
                    ]
                )
            )
        elif operator in {"==", "!="}:
            if operator == "==":
                exact = _range_result(">=", boundary, low, high)
                # An exact match is only invariant when it is outside the entire
                # selected-minor interval.  Otherwise a patch fact is required.
                results.append(
                    MinorPythonCompatibility.INCOMPATIBLE
                    if exact == MinorPythonCompatibility.INCOMPATIBLE
                    else MinorPythonCompatibility.UNPROVABLE
                )
            else:
                # Unlike equality, an exact exclusion is certainly satisfied
                # whenever its excluded point is outside this minor's complete
                # [low, high) patch interval.  A point inside that interval
                # needs an exact patch fact and therefore remains unprovable.
                results.append(
                    MinorPythonCompatibility.UNPROVABLE
                    if low <= boundary < high
                    else MinorPythonCompatibility.COMPATIBLE
                )
        else:
            results.append(MinorPythonCompatibility.UNPROVABLE)
    return _combine_minor_results(results)


def python_satisfies(version: str, requires_python: str | None) -> bool:
    """Return true only for a compatibility proof, preserving the legacy API."""

    try:
        return (
            minor_python_compatibility(version, requires_python)
            == MinorPythonCompatibility.COMPATIBLE
        )
    except (InvalidSpecifier, ValueError):
        return False


def candidate_python_versions(assessment: RepositoryAssessment) -> list[str]:
    ordered = list(PYTHON_POLICY_ORDER)
    explicit = assessment.python.python_version_file
    if explicit:
        match = re.match(r"^(\d+\.\d+)", explicit.strip())
        if match:
            minor = match.group(1)
            ordered = [minor, *[item for item in ordered if item != minor]]
    return list(dict.fromkeys(ordered))
