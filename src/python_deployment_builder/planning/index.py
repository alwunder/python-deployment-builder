"""Explicit, non-building PyPI wheel inspection used by planning."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging._parser import Variable
from packaging.markers import InvalidMarker, Marker, _evaluate_markers
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from python_deployment_builder.models import (
    DependencyAssessment,
    FindingStatus,
    OnlineCompatibilityAssessment,
    OnlineIndexContext,
    WheelCompatibility,
)

PYPI_JSON_BASE = "https://pypi.org/pypi"
JsonFetcher = Callable[[str], dict[str, Any]]
class TargetMarkerEnvironmentError(ValueError):
    """A marker requires target facts PDB does not select for M6.1."""


class TargetMarkerApplicability(StrEnum):
    """Whether an environment marker can be proven for PDB's target contract."""

    APPLIES = "applies"
    DOES_NOT_APPLY = "does_not_apply"
    UNPROVABLE = "unprovable"


_PATCH_SENSITIVE_MARKER_VARIABLES = {
    "implementation_version",
    "python_full_version",
}


def target_marker_environment(
    python_version: str, architecture: str, *, extra: str = ""
) -> dict[str, str]:
    """Return every PEP 508 marker value PDB can establish for its Windows target."""

    # PDB selects a Python major/minor, not an exact patch.  Deliberately omit
    # patch-sensitive variables instead of fabricating ``<minor>.0``.  Likewise
    # platform_release and platform_version have no planned target values.
    return {
        "implementation_name": "cpython",
        "os_name": "nt",
        "platform_machine": "AMD64" if architecture == "x86_64" else "ARM64",
        "platform_python_implementation": "CPython",
        "platform_system": "Windows",
        "python_version": python_version,
        "sys_platform": "win32",
        "extra": extra,
    }


def _marker_variables(value: object) -> set[str]:
    """Read variable nodes from packaging's already parsed marker expression."""

    if isinstance(value, Variable):
        return {value.value}
    if isinstance(value, (list, tuple)):
        return set().union(*(_marker_variables(item) for item in value))
    return set()


def target_marker_applicability(
    marker: str | None,
    python_version: str,
    architecture: str,
    *,
    extra: str = "",
) -> TargetMarkerApplicability:
    """Evaluate a marker without inventing unselected target facts."""

    if not marker:
        return TargetMarkerApplicability.APPLIES
    try:
        parsed = Marker(marker)
    except InvalidMarker as exc:
        raise TargetMarkerEnvironmentError(f"Malformed environment marker: {marker!r}") from exc
    environment = target_marker_environment(python_version, architecture, extra=extra)
    unprovable = sorted(_marker_variables(parsed._markers) - set(environment))
    if unprovable:
        return TargetMarkerApplicability.UNPROVABLE
    return (
        TargetMarkerApplicability.APPLIES
        # ``Marker.evaluate`` begins from the builder host's default environment
        # before applying overrides.  The target environment must be complete for
        # the variables we use and contain no host-derived fallback values.
        if _evaluate_markers(parsed._markers, environment)
        else TargetMarkerApplicability.DOES_NOT_APPLY
    )


def target_marker_applies(
    marker: str | None,
    python_version: str,
    architecture: str,
    *,
    extra: str = "",
) -> bool:
    """Strict target-marker evaluation for proofs that require certainty."""

    applicability = target_marker_applicability(
        marker, python_version, architecture, extra=extra
    )
    if applicability == TargetMarkerApplicability.UNPROVABLE:
        try:
            variables = sorted(
                _marker_variables(Marker(marker or "")._markers)
                - set(target_marker_environment(python_version, architecture, extra=extra))
            )
        except InvalidMarker:  # already translated by target_marker_applicability
            variables = []
        patch_sensitive = sorted(set(variables) & _PATCH_SENSITIVE_MARKER_VARIABLES)
        detail = (
            "patch-sensitive target facts are selected only by Python major/minor: "
            + ", ".join(patch_sensitive)
            if patch_sensitive
            else "target marker fields are not selected by PDB: " + ", ".join(variables)
        )
        raise TargetMarkerEnvironmentError(detail)
    return applicability == TargetMarkerApplicability.APPLIES


def _fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "python-deployment-builder/0.1"})
    with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed HTTPS index
        return json.load(response)


def _specifier(value: str) -> SpecifierSet:
    value = value.split(";", 1)[0].strip()
    try:
        return SpecifierSet(value)
    except InvalidSpecifier:
        return SpecifierSet()


def _release_version(
    data: dict[str, Any], constraint: str, python_version: str
) -> str | None:
    specifier = _specifier(constraint)
    versions: list[Version] = []
    for raw_version, files in data.get("releases", {}).items():
        if not files:
            continue
        try:
            version = Version(raw_version)
        except InvalidVersion:
            continue
        if not version.is_prerelease and version in specifier:
            versions.append(version)
    for version in sorted(versions, reverse=True):
        files = data.get("releases", {}).get(str(version), [])
        if any(_supports_python(item.get("requires_python"), python_version) for item in files):
            return str(version)
    return None


def _supports_python(requires_python: str | None, python_version: str) -> bool:
    if not requires_python:
        return True
    try:
        return f"{python_version}.0" in SpecifierSet(requires_python)
    except InvalidSpecifier:
        return True


def marker_applies(
    marker: str | None,
    python_version: str,
    architecture: str,
    *,
    extra: str = "",
) -> bool:
    if not marker:
        return True
    try:
        return (
            target_marker_applicability(marker, python_version, architecture, extra=extra)
            != TargetMarkerApplicability.DOES_NOT_APPLY
        )
    except TargetMarkerEnvironmentError:
        # Planning remains conservative for malformed or host-unknown lock markers;
        # first-party wheel validation raises instead of treating them as proven.
        return True


def wheel_matches(filename: str, python_version: str, architecture: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    try:
        _, _, _, wheel_tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return False
    platform = "win_amd64" if architecture == "x86_64" else "win_arm64"
    major, minor = (int(part) for part in python_version.split(".", 1))
    supported = set(cpython_tags((major, minor), platforms=[platform]))
    supported.update(
        compatible_tags(
            (major, minor),
            interpreter=f"cp{major}{minor}",
            platforms=[platform],
        )
    )
    return bool(wheel_tags & supported)


def inspect_dependency_wheels(
    dependencies: list[DependencyAssessment],
    python_versions: list[str],
    architecture: str = "x86_64",
    fetcher: JsonFetcher = _fetch_json,
) -> OnlineCompatibilityAssessment:
    """Inspect published files only; never download/build distributions or execute target code."""

    context = OnlineIndexContext(
        assessed_at=datetime.now(UTC),
        index_name="PyPI JSON API",
        index_url=PYPI_JSON_BASE,
        python_targets=python_versions,
        windows_architecture=architecture,
    )
    results: list[WheelCompatibility] = []
    errors: list[str] = []
    for dependency in dependencies:
        url = f"{PYPI_JSON_BASE}/{quote(dependency.distribution_name)}/json"
        try:
            data = fetcher(url)
            for python_version in python_versions:
                extra = dependency.group if dependency.group != "runtime" else ""
                if not marker_applies(
                    dependency.environment_marker,
                    python_version,
                    architecture,
                    extra=extra,
                ):
                    continue
                resolved = _release_version(
                    data, dependency.declared_constraint, python_version
                )
                files = data.get("releases", {}).get(resolved, []) if resolved else []
                compatible_files = [
                    item.get("filename", "")
                    for item in files
                    if _supports_python(item.get("requires_python"), python_version)
                ]
                wheels = sorted(
                    filename
                    for filename in compatible_files
                    if wheel_matches(filename, python_version, architecture)
                )
                sdist = any(filename.endswith(('.tar.gz', '.zip')) for filename in compatible_files)
                results.append(
                    WheelCompatibility(
                        distribution_name=dependency.distribution_name,
                        declared_constraint=dependency.declared_constraint,
                        resolved_version=resolved,
                        python_version=python_version,
                        wheel_available=bool(wheels),
                        matching_wheels=wheels,
                        source_distribution_available=sdist,
                        status=(
                            FindingStatus.DETECTED if wheels else FindingStatus.NEEDS_VALIDATION
                        ),
                        detail=(
                            "Compatible published wheel detected."
                            if wheels
                            else (
                                "No compatible wheel detected for the selected release; "
                                "source builds remain disabled."
                            )
                        ),
                    )
                )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"{dependency.distribution_name}: {exc}")
    return OnlineCompatibilityAssessment(context=context, dependencies=results, errors=errors)
