"""Explicit, testable choices made independently of repository analysis."""

from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from python_deployment_builder.models import RepositoryAssessment

PYTHON_POLICY_ORDER = ("3.12", "3.13", "3.11", "3.14")


def safe_application_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized[:64] or "python-application"


def python_satisfies(version: str, requires_python: str | None) -> bool:
    if not requires_python:
        return True
    try:
        return f"{version}.0" in SpecifierSet(requires_python)
    except InvalidSpecifier:
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
