"""Explicit, non-building PyPI wheel inspection used by planning."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging.specifiers import InvalidSpecifier, SpecifierSet
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


def _wheel_matches(filename: str, python_version: str, architecture: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    platform = "win_amd64" if architecture == "x86_64" else "win_arm64"
    if filename.endswith("-py3-none-any.whl") or filename.endswith("-py2.py3-none-any.whl"):
        return True
    if not filename.endswith(f"-{platform}.whl"):
        return False
    minor_tag = python_version.replace(".", "")
    if re.search(rf"-cp{minor_tag}-(?:cp{minor_tag}|abi3)-", filename):
        return True
    abi3 = re.search(r"-cp(3\d+)-abi3-", filename)
    return bool(abi3 and int(abi3.group(1)) <= int(minor_tag))


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
        if dependency.group != "runtime":
            continue
        url = f"{PYPI_JSON_BASE}/{quote(dependency.distribution_name)}/json"
        try:
            data = fetcher(url)
            for python_version in python_versions:
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
                    if _wheel_matches(filename, python_version, architecture)
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
