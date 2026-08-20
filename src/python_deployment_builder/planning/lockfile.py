"""Static uv.lock graph and artifact-policy inspection."""

from __future__ import annotations

import tomllib
from collections import deque
from pathlib import Path
from urllib.parse import unquote, urlsplit

from packaging.utils import canonicalize_name

from python_deployment_builder.models import (
    ArtifactAvailability,
    ArtifactPolicyFinding,
    DependencyEdge,
    DeploymentArtifactRequirement,
    LockedDependency,
    LockGraphAssessment,
)
from python_deployment_builder.planning.index import marker_applies, wheel_matches


def _filename(artifact: dict[str, object]) -> str:
    url = artifact.get("url")
    return unquote(Path(urlsplit(url).path).name) if isinstance(url, str) else ""


def _edge_applies(
    edge: dict[str, object], python_version: str, architecture: str, extra: str | None
) -> bool:
    marker = edge.get("marker")
    return marker_applies(
        marker if isinstance(marker, str) else None,
        python_version,
        architecture,
        extra=extra or "",
    )


def _resolve_package(
    packages: list[dict[str, object]], edge: dict[str, object]
) -> dict[str, object] | None:
    name = edge.get("name")
    if not isinstance(name, str):
        return None
    candidates = [
        package
        for package in packages
        if canonicalize_name(str(package.get("name", ""))) == canonicalize_name(name)
    ]
    version = edge.get("version")
    if isinstance(version, str):
        candidates = [package for package in candidates if package.get("version") == version]
    return candidates[0] if len(candidates) == 1 else None


def inspect_uv_lock(
    repository_root: Path,
    application_name: str,
    python_version: str,
    architecture: str,
    selected_extras: list[str],
) -> LockGraphAssessment:
    path = repository_root / "uv.lock"
    if not path.is_file():
        return LockGraphAssessment(
            inspected=False,
            python_version=python_version,
            architecture=architecture,
            selected_extras=selected_extras,
            limitations=["uv.lock is absent; no locked transitive graph can be inspected."],
        )
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return LockGraphAssessment(
            inspected=False,
            python_version=python_version,
            architecture=architecture,
            selected_extras=selected_extras,
            limitations=[f"uv.lock could not be parsed statically: {exc}"],
        )

    packages = [item for item in document.get("package", []) if isinstance(item, dict)]
    root = next(
        (
            package
            for package in packages
            if canonicalize_name(str(package.get("name", "")))
            == canonicalize_name(application_name)
        ),
        None,
    )
    if root is None:
        return LockGraphAssessment(
            inspected=False,
            python_version=python_version,
            architecture=architecture,
            selected_extras=selected_extras,
            limitations=["The application package was not identifiable in uv.lock."],
        )

    root_name = str(root.get("name", application_name))
    queued: deque[tuple[dict[str, object], list[str], bool, str | None]] = deque()
    edges: list[DependencyEdge] = []

    def enqueue_edges(
        parent: str,
        values: object,
        chain: list[str],
        direct: bool,
        selected_extra: str | None,
    ) -> None:
        if not isinstance(values, list):
            return
        for raw_edge in values:
            if not isinstance(raw_edge, dict) or not isinstance(raw_edge.get("name"), str):
                continue
            applies = _edge_applies(raw_edge, python_version, architecture, selected_extra)
            marker = raw_edge.get("marker")
            edges.append(
                DependencyEdge(
                    from_package=parent,
                    to_package=str(raw_edge["name"]),
                    marker=marker if isinstance(marker, str) else None,
                    applicable=applies,
                    selected_extra=selected_extra,
                )
            )
            if not applies:
                continue
            package = _resolve_package(packages, raw_edge)
            if package is not None:
                queued.append(
                    (package, [*chain, str(raw_edge["name"])], direct, selected_extra)
                )

    enqueue_edges(root_name, root.get("dependencies"), [root_name], True, None)
    optional = root.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra in selected_extras:
            enqueue_edges(root_name, optional.get(extra), [root_name], True, extra)

    locked: dict[tuple[str, str], LockedDependency] = {}
    expanded: set[tuple[str, str, str | None]] = set()
    while queued:
        package, chain, direct, selected_extra = queued.popleft()
        name = str(package.get("name", chain[-1]))
        version = str(package.get("version", "unversioned"))
        key = (canonicalize_name(name), version)
        expansion_key = (*key, selected_extra)
        wheels = [
            filename
            for item in package.get("wheels", [])
            if isinstance(item, dict)
            and (filename := _filename(item))
            and wheel_matches(filename, python_version, architecture)
        ]
        sdist = isinstance(package.get("sdist"), dict)
        if wheels:
            policy = "wheel_usable"
        elif sdist:
            policy = "developer_wheel_required"
        else:
            policy = "no_artifact"
        candidate = LockedDependency(
            name=name,
            version=version,
            direct=direct,
            dependency_chain=chain,
            selected_extra=selected_extra,
            artifact=ArtifactAvailability(
                compatible_wheel_available=bool(wheels),
                matching_wheels=sorted(wheels),
                source_distribution_available=sdist,
                policy=policy,
            ),
        )
        existing = locked.get(key)
        if existing is None or len(chain) < len(existing.dependency_chain):
            locked[key] = candidate
        if expansion_key in expanded:
            continue
        expanded.add(expansion_key)
        enqueue_edges(name, package.get("dependencies"), chain, False, selected_extra)

    dependencies = sorted(locked.values(), key=lambda item: (not item.direct, item.name.lower()))
    findings: list[ArtifactPolicyFinding] = []
    requirements: list[DeploymentArtifactRequirement] = []
    for dependency in dependencies:
        if dependency.artifact.policy == "wheel_usable":
            continue
        status = (
            "developer_artifact_required"
            if dependency.artifact.source_distribution_available
            else "unavailable"
        )
        findings.append(
            ArtifactPolicyFinding(
                code="SOURCE_ONLY_LOCKED_DEPENDENCY"
                if status == "developer_artifact_required"
                else "LOCKED_DEPENDENCY_NO_ARTIFACT",
                package=dependency.name,
                version=dependency.version,
                status=status,
                dependency_chain=dependency.dependency_chain,
                selected_extra=dependency.selected_extra,
                description=(
                    "No compatible locked wheel is available. End-user source builds remain "
                    "disabled; developer preparation must supply an approved wheel."
                    if status == "developer_artifact_required"
                    else "The lockfile contains no compatible wheel or source artifact."
                ),
            )
        )
        if status == "developer_artifact_required":
            requirements.append(
                DeploymentArtifactRequirement(
                    package=dependency.name,
                    version=dependency.version,
                    action="developer_wheel_required",
                    reason="The selected locked graph has no compatible Windows wheel.",
                )
            )
    return LockGraphAssessment(
        inspected=True,
        python_version=python_version,
        architecture=architecture,
        selected_extras=selected_extras,
        dependencies=dependencies,
        edges=edges,
        artifact_findings=findings,
        artifact_requirements=requirements,
    )
