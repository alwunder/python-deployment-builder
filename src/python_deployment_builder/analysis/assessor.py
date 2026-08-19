"""High-level static repository assessment pipeline."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.analysis.dependencies import (
    apparently_unused_dependencies,
    enrich_dependencies,
)
from python_deployment_builder.analysis.imports import scan_imports
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import (
    MaterializedRepository,
    repository_fingerprint,
)
from python_deployment_builder.analysis.resources import inspect_resources
from python_deployment_builder.analysis.risks import build_risks, rate_suitability
from python_deployment_builder.analysis.runtime_assumptions import scan_runtime_assumptions
from python_deployment_builder.models import RepositoryAssessment, RepositoryIdentity


def _git_revision(root: Path) -> str | None:
    """Read a normal .git HEAD without invoking Git or following arbitrary files."""

    git_dir = root / ".git"
    head_path = git_dir / "HEAD"
    if not head_path.is_file():
        return None
    try:
        head = head_path.read_text(encoding="ascii").strip()
        if head.startswith("ref: "):
            ref = head.removeprefix("ref: ")
            if not ref.startswith("refs/") or not re.fullmatch(r"[A-Za-z0-9_./-]+", ref):
                return None
            if ".." in Path(ref).parts:
                return None
            ref_path = git_dir / ref
            return ref_path.read_text(encoding="ascii").strip() if ref_path.is_file() else None
        return head if len(head) >= 7 else None
    except OSError:
        return None


def assess_repository(repository: MaterializedRepository) -> RepositoryAssessment:
    """Run the complete non-executing Milestone 1 assessment."""

    root = repository.root
    metadata = inspect_metadata(root)
    imports = scan_imports(root, metadata.project.source_roots, metadata.dependencies)
    dependencies = enrich_dependencies(metadata.dependencies, imports.observations)
    runtime = scan_runtime_assumptions(root, metadata.project.source_roots)
    resources, resource_configuration = inspect_resources(root, metadata.project.source_roots)
    configuration = [*runtime.configuration_requirements, *resource_configuration]
    risks = build_risks(
        metadata.project,
        dependencies,
        imports.observations,
        runtime.runtime_requirements,
        resources,
        runtime.write_locations,
        configuration,
    )
    rating, summary = rate_suitability(risks)
    limitations = [
        "Static assessment did not import or execute target-project code.",
        "Package index and Windows wheel availability were not queried.",
        "Import-to-distribution matching uses declared metadata plus a conservative mapping table.",
        "Write-location and launch-critical classifications are heuristic until "
        "runtime validation.",
    ]
    for parse_error in [*imports.parse_errors, *runtime.parse_errors]:
        limitations.append(f"Python source could not be parsed: {parse_error}")
    revision = _git_revision(root)
    if revision is None and repository.source_kind == "github_archive":
        archive_revision = re.search(r"-([0-9a-f]{7,40})$", root.name, flags=re.IGNORECASE)
        revision = archive_revision.group(1) if archive_revision else None
    return RepositoryAssessment(
        generated_at=datetime.now(UTC),
        tool_version=__version__,
        repository=RepositoryIdentity(
            source=repository.source,
            source_kind=repository.source_kind,
            root_name=root.name,
            revision=revision,
            fingerprint=repository_fingerprint(root),
        ),
        project=metadata.project,
        python=metadata.python,
        dependencies=dependencies,
        imports=imports.observations,
        declared_but_apparently_unused=apparently_unused_dependencies(
            dependencies, imports.observations
        ),
        runtime_requirements=runtime.runtime_requirements,
        resources=resources,
        write_locations=runtime.write_locations,
        configuration_requirements=configuration,
        risks=risks,
        rating=rating,
        rating_summary=summary,
        analysis_limitations=limitations,
    )
