"""Role-aware repository inventory and deployment-support evidence."""

from __future__ import annotations

import ast
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from pathspec import PathSpec

from python_deployment_builder.models import (
    AnalysisScopeSummary,
    DependencyAssessment,
    DeploymentSupportFinding,
    Evidence,
    FindingStatus,
    RepositoryFileInventoryItem,
    RepositoryFileRole,
    ResourceRequirement,
    VendorRuntimeEvidence,
    WriteLocation,
)

TEST_DIRECTORIES = {"test", "tests"}
DOCUMENTATION_DIRECTORIES = {"doc", "docs", "documentation"}
EXAMPLE_DIRECTORIES = {"example", "examples", "snippet", "snippets", "notebooks"}
DEPLOYMENT_DIRECTORIES = {"deployment"}
DEVELOPMENT_DIRECTORIES = {
    ".github",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "build",
    "dist",
}
LOCAL_DIRECTORIES = {
    ".git",
    ".hg",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}
PYTHON_CACHE_DIRECTORY = re.compile(r"^__pycache__(?:\s*\(\d+\))?$", re.IGNORECASE)
CONVENTIONAL_RUNTIME_RESOURCE_KINDS = {
    "assets",
    "configuration",
    "icons",
    "profiles",
    "prompts",
    "schemas",
    "templates",
}


def resource_covers_inventory_path(resource_path: str, inventory_path: str) -> bool:
    """Return whether a repository-relative resource includes an inventory member.

    Resource analysis intentionally records both concrete files and conventional
    directories.  Compare path *components*, not textual prefixes: ``assets``
    includes ``assets/view.html`` but never ``assets2/view.html``.
    """

    resource = PurePosixPath(resource_path.rstrip("/"))
    candidate = PurePosixPath(inventory_path.rstrip("/"))
    return candidate.parts[: len(resource.parts)] == resource.parts


DOCUMENTATION_SUFFIXES = {".md", ".rst"}
DEVELOPMENT_FILENAMES = {
    ".gitignore",
    ".python-version",
    "pdbuilder.toml",
    "pyproject.toml",
    "ruff.toml",
    "setup.cfg",
    "setup.py",
    "tox.ini",
}


@dataclass(frozen=True)
class InventoryResult:
    items: list[RepositoryFileInventoryItem]
    application_files: list[Path]
    summary: AnalysisScopeSummary


def _ignore_spec(path: Path) -> PathSpec:
    if not path.is_file():
        return PathSpec.from_lines("gitwildmatch", [])
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    return PathSpec.from_lines("gitwildmatch", lines)


def _ignore_match(spec: PathSpec, candidate: str) -> bool | None:
    matched: bool | None = None
    for pattern in spec.patterns:
        if pattern.include is not None and next(iter(pattern.match([candidate])), None) is not None:
            matched = bool(pattern.include)
    return matched


def _is_ignored(
    root: Path,
    relative: Path,
    cache: dict[Path, PathSpec],
) -> bool:
    """Apply root and nested .gitignore files with Git-relative precedence."""

    directories = [Path(".")]
    current = Path(".")
    for part in relative.parent.parts:
        current /= part
        directories.append(current)
    ignored = False
    for directory in directories:
        ignore_file = root / directory / ".gitignore"
        spec = cache.setdefault(directory, _ignore_spec(ignore_file))
        candidate = relative.relative_to(directory).as_posix()
        result = _ignore_match(spec, candidate)
        if result is not None:
            ignored = result
    return ignored


def _under_source_root(relative: Path, source_roots: list[str]) -> bool:
    for source_root in source_roots:
        normalized = Path(source_root)
        if normalized == Path("."):
            return True
        try:
            relative.relative_to(normalized)
            return True
        except ValueError:
            continue
    return False


def _classify(
    relative: Path, source_roots: list[str], ignored: bool
) -> tuple[RepositoryFileRole, str]:
    parts = {part.lower() for part in relative.parts[:-1]}
    name = relative.name.lower()
    if (
        ignored
        or parts & LOCAL_DIRECTORIES
        or any(PYTHON_CACHE_DIRECTORY.fullmatch(part) for part in parts)
        or name.endswith((".pyc", ".pyo"))
    ):
        return (
            RepositoryFileRole.IGNORED_OR_LOCAL,
            "Excluded by repository ignore/local-state policy.",
        )
    if parts & TEST_DIRECTORIES or name.startswith("test_") or name.endswith("_test.py"):
        return RepositoryFileRole.TEST, "Located in a conventional test scope."
    if parts & DOCUMENTATION_DIRECTORIES or relative.suffix.lower() in DOCUMENTATION_SUFFIXES:
        return (
            RepositoryFileRole.DOCUMENTATION,
            "Located in documentation scope or uses a documentation format.",
        )
    if parts & EXAMPLE_DIRECTORIES or relative.suffix.lower() == ".ipynb":
        return (
            RepositoryFileRole.EXAMPLE_OR_SNIPPET,
            "Located in an example, snippet, or notebook scope.",
        )
    if parts & DEPLOYMENT_DIRECTORIES or (
        relative.parent == Path(".")
        and relative.suffix.lower() in {".bat", ".cmd"}
        and any(word in name for word in ("run", "repair", "diagnose", "setup", "install"))
    ):
        return (
            RepositoryFileRole.DEPLOYMENT_SUPPORT,
            "Existing deployment launcher or support scope.",
        )
    if parts & DEVELOPMENT_DIRECTORIES or name in DEVELOPMENT_FILENAMES:
        return RepositoryFileRole.DEVELOPMENT_TOOLING, "Repository development/build tooling."
    if relative.suffix.lower() == ".py" and _under_source_root(relative, source_roots):
        return (
            RepositoryFileRole.APPLICATION_SOURCE,
            "Python source beneath a configured or inferred source root.",
        )
    return RepositoryFileRole.UNKNOWN, "No high-confidence runtime or repository role was inferred."


def inventory_repository(root: Path, source_roots: list[str]) -> InventoryResult:
    """Inventory paths once so application scanners share an explicit scope."""

    ignore_specs: dict[Path, PathSpec] = {}
    items: list[RepositoryFileInventoryItem] = []
    application_files: list[Path] = []
    for current, directory_names, file_names in os.walk(root):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        retained: list[str] = []
        for directory_name in sorted(directory_names):
            relative = relative_current / directory_name
            posix = relative.as_posix()
            local = (
                directory_name.lower() in LOCAL_DIRECTORIES
                or PYTHON_CACHE_DIRECTORY.fullmatch(directory_name) is not None
            )
            if local:
                items.append(
                    RepositoryFileInventoryItem(
                        path=posix + "/",
                        role=RepositoryFileRole.IGNORED_OR_LOCAL,
                        included_in_runtime_scan=False,
                        reason="Ignored directory was pruned before application analysis.",
                        evidence=[
                            Evidence(
                                file=".gitignore", detail=f"Ignore/local rule matched {posix}/."
                            )
                        ],
                    )
                )
            elif directory_name.lower() in DEVELOPMENT_DIRECTORIES:
                items.append(
                    RepositoryFileInventoryItem(
                        path=posix + "/",
                        role=RepositoryFileRole.DEVELOPMENT_TOOLING,
                        included_in_runtime_scan=False,
                        reason="Development/build directory was pruned from runtime analysis.",
                        evidence=[
                            Evidence(file=posix, detail="Conventional development/build scope.")
                        ],
                    )
                )
            else:
                # Descend into gitignored directories so later negation rules can
                # re-include children according to gitwildmatch semantics.
                retained.append(directory_name)
        directory_names[:] = retained
        for file_name in sorted(file_names):
            path = current_path / file_name
            relative = path.relative_to(root)
            posix = relative.as_posix()
            if path.is_symlink():
                items.append(
                    RepositoryFileInventoryItem(
                        path=posix,
                        role=RepositoryFileRole.IGNORED_OR_LOCAL,
                        included_in_runtime_scan=False,
                        reason="Symbolic links are excluded from untrusted application analysis.",
                        evidence=[Evidence(file=posix, detail="Repository symbolic link.")],
                    )
                )
                continue
            ignored = _is_ignored(root, relative, ignore_specs)
            role, reason = _classify(relative, source_roots, ignored)
            include = role == RepositoryFileRole.APPLICATION_SOURCE
            item = RepositoryFileInventoryItem(
                path=posix,
                role=role,
                included_in_runtime_scan=include,
                reason=reason,
                evidence=[Evidence(file=posix, detail=reason)],
            )
            items.append(item)
            if include:
                application_files.append(path)
    items.sort(key=lambda item: item.path.lower())
    application_files.sort()
    return InventoryResult(items, application_files, summarize_inventory(items))


def _imported_modules(tree: ast.AST) -> list[tuple[str, int]]:
    modules: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.append((node.module, node.lineno))
            modules.extend(
                (f"{node.module}.{alias.name}", node.lineno)
                for alias in node.names
                if alias.name != "*"
            )
    return modules


def _module_files(root: Path, module: str) -> list[Path]:
    relative = Path(*module.split("."))
    candidates = [
        root / relative.with_suffix(".py"),
        root / relative / "__init__.py",
        root / "src" / relative.with_suffix(".py"),
        root / "src" / relative / "__init__.py",
    ]
    return [path for path in candidates if path.is_file()]


def promote_imported_application_files(
    root: Path,
    items: list[RepositoryFileInventoryItem],
    application_files: list[Path],
) -> None:
    """Promote non-ignored Python modules imported by production source."""

    by_path = {item.path: item for item in items}
    queued = list(application_files)
    scanned: set[Path] = set()
    while queued:
        source_path = queued.pop(0)
        if source_path in scanned:
            continue
        scanned.add(source_path)
        relative_source = source_path.relative_to(root).as_posix()
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8-sig"), filename=relative_source)
        except (OSError, SyntaxError, UnicodeError):
            continue
        for module, line in _imported_modules(tree):
            for imported_path in _module_files(root, module):
                relative = imported_path.relative_to(root).as_posix()
                item = by_path.get(relative)
                if item is None or item.role == RepositoryFileRole.APPLICATION_SOURCE:
                    continue
                evidence = Evidence(
                    file=relative_source,
                    line=line,
                    detail=f"Application source imports local module {module!r}.",
                )
                item.evidence.append(evidence)
                if item.role == RepositoryFileRole.IGNORED_OR_LOCAL:
                    item.reason = (
                        "Application source imports this ignored/local module; it remains excluded "
                        "and must be resolved explicitly."
                    )
                    continue
                item.role = RepositoryFileRole.APPLICATION_SOURCE
                item.included_in_runtime_scan = True
                item.reason = (
                    "Promoted to application source because production source imports this module."
                )
                application_files.append(imported_path)
                queued.append(imported_path)
    application_files.sort()


def summarize_inventory(items: list[RepositoryFileInventoryItem]) -> AnalysisScopeSummary:
    counts = Counter(item.role for item in items)
    return AnalysisScopeSummary(
        application_source_files=counts[RepositoryFileRole.APPLICATION_SOURCE],
        runtime_resources=counts[RepositoryFileRole.RUNTIME_RESOURCE],
        mutable_state_candidates=counts[RepositoryFileRole.MUTABLE_STATE_CANDIDATE],
        deployment_support_files=counts[RepositoryFileRole.DEPLOYMENT_SUPPORT],
        tests_excluded=counts[RepositoryFileRole.TEST],
        documentation_excluded=counts[RepositoryFileRole.DOCUMENTATION],
        examples_excluded=counts[RepositoryFileRole.EXAMPLE_OR_SNIPPET],
        development_tooling_excluded=counts[RepositoryFileRole.DEVELOPMENT_TOOLING],
        ignored_local_excluded=counts[RepositoryFileRole.IGNORED_OR_LOCAL],
        unknown_role_files=counts[RepositoryFileRole.UNKNOWN],
    )


def apply_resource_roles(
    items: list[RepositoryFileInventoryItem], resources: list[ResourceRequirement]
) -> AnalysisScopeSummary:
    """Promote only statically supported resource paths in the inventory."""

    applicable_resources = [
        resource
        for resource in resources
        if resource.status == FindingStatus.DETECTED
        or resource.kind in CONVENTIONAL_RUNTIME_RESOURCE_KINDS
    ]
    for item in items:
        matching = [
            resource
            for resource in applicable_resources
            if resource_covers_inventory_path(resource.path, item.path)
        ]
        authoritative = any(
            resource.packaging_status == "packaged" for resource in matching
        )
        if matching and item.role not in {
            RepositoryFileRole.APPLICATION_SOURCE,
            RepositoryFileRole.IGNORED_OR_LOCAL,
            RepositoryFileRole.MUTABLE_STATE_CANDIDATE,
        } and (
            not authoritative
            or item.role
            in {
                RepositoryFileRole.UNKNOWN,
                RepositoryFileRole.DOCUMENTATION,
                RepositoryFileRole.EXAMPLE_OR_SNIPPET,
                RepositoryFileRole.RUNTIME_RESOURCE,
            }
        ):
            item.role = RepositoryFileRole.RUNTIME_RESOURCE
            item.included_in_runtime_scan = False
            if authoritative:
                item.reason = (
                    "Authoritative setuptools package-data metadata identifies this "
                    "runtime resource."
                )
                item.evidence.extend(
                    evidence
                    for resource in matching
                    if resource.packaging_status == "packaged"
                    for evidence in resource.evidence
                    if evidence not in item.evidence
                )
            else:
                item.reason = "Application source contains a static runtime reference to this path."
    return summarize_inventory(items)


def apply_mutable_state_roles(
    items: list[RepositoryFileInventoryItem],
    resources: list[ResourceRequirement],
    writes: list[WriteLocation],
) -> AnalysisScopeSummary:
    """Promote existing resources when write expressions identify their filenames."""

    del writes  # Resource access modes carry stronger path-specific evidence.
    mutable_paths = {
        resource.path
        for resource in resources
        if resource.access_mode in {"write", "read_write"}
    }
    for item in items:
        if item.path in mutable_paths:
            item.role = RepositoryFileRole.MUTABLE_STATE_CANDIDATE
            item.included_in_runtime_scan = False
            resource = next(value for value in resources if value.path == item.path)
            item.reason = (
                f"Static {resource.access_mode} path-use evidence identifies mutable state."
            )
            item.evidence.extend(resource.evidence[1:])
    return summarize_inventory(items)


def classify_ignored_mutable_state(
    items: list[RepositoryFileInventoryItem],
    resources: list[ResourceRequirement],
) -> AnalysisScopeSummary:
    """Distinguish ignored local state/cache files from omitted immutable resources."""

    by_path = {item.path: item for item in items}
    for resource in resources:
        item = by_path.get(resource.path)
        if item is None or item.role != RepositoryFileRole.IGNORED_OR_LOCAL:
            continue
        if resource.access_mode not in {"write", "read_write"}:
            continue
        item.role = RepositoryFileRole.MUTABLE_STATE_CANDIDATE
        item.included_in_runtime_scan = False
        item.reason = (
            f"Ignored referenced file has static {resource.access_mode} path-use evidence and is "
            "treated as mutable local state, not an immutable packaged resource."
        )
        item.evidence.extend(resource.evidence[1:])
    return summarize_inventory(items)


def inspect_deployment_support(
    root: Path, items: list[RepositoryFileInventoryItem]
) -> tuple[
    list[DeploymentSupportFinding],
    list[VendorRuntimeEvidence],
    list[DependencyAssessment],
]:
    """Describe existing deployment machinery without treating it as application code."""

    support = [item for item in items if item.role == RepositoryFileRole.DEPLOYMENT_SUPPORT]
    findings: list[DeploymentSupportFinding] = []
    corpus: list[tuple[RepositoryFileInventoryItem, str]] = []
    support_dependencies: list[DependencyAssessment] = []
    for item in support:
        path = root / item.path
        text = ""
        if path.is_file() and path.suffix.lower() in {".py", ".bat", ".cmd", ".txt", ".toml"}:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        corpus.append((item, text))
        lowered_name = path.name.lower()
        if path.suffix.lower() == ".txt" and any(
            token in lowered_name for token in ("constraints", "requirements")
        ):
            for line_number, raw_line in enumerate(text.splitlines(), start=1):
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    requirement = Requirement(line)
                except InvalidRequirement:
                    continue
                support_dependencies.append(
                    DependencyAssessment(
                        distribution_name=requirement.name,
                        declared_constraint=str(requirement.specifier) or "unconstrained",
                        group="deployment_support",
                        launch_critical=False,
                        evidence=[
                            Evidence(
                                file=item.path,
                                line=line_number,
                                detail="Dependency constrained only by deployment support.",
                                excerpt=raw_line.strip(),
                            )
                        ],
                    )
                )
        if "repair" in lowered_name:
            category = "repair_script"
        elif "diagnos" in lowered_name:
            category = "diagnostic_script"
        elif path.suffix.lower() in {".bat", ".cmd"} and "run" in lowered_name:
            category = "launch_script"
        elif re.search(r"(?i)(clone|environment|venv|python\s+install|uv\s+python)", text):
            category = "environment_provisioning"
        else:
            category = "other"
        findings.append(
            DeploymentSupportFinding(
                category=category,
                name=path.name,
                description=(
                    "Existing repository deployment-support file; excluded from application "
                    "import analysis."
                ),
                evidence=[Evidence(file=item.path, detail=item.reason)],
            )
        )
    joined = "\n".join(text for _, text in corpus).lower()
    registry_evidence = [
        item for item, text in corpus if "winreg" in text.lower() or "registry" in text.lower()
    ]
    if registry_evidence:
        findings.append(
            DeploymentSupportFinding(
                category="registry_discovery",
                name="Windows registry discovery",
                description="Existing deployment support inspects the Windows registry.",
                evidence=[
                    Evidence(file=item.path, detail="Registry discovery in deployment support.")
                    for item in registry_evidence
                ],
            )
        )
    runtime_evidence = [
        item
        for item, text in corpus
        if re.search(r"(?i)(clone|environment|localappdata|fingerprint|state)", text)
    ]
    if runtime_evidence:
        findings.append(
            DeploymentSupportFinding(
                category="runtime_management",
                name="Existing per-user runtime management",
                description="Deployment support contains environment/state management behavior.",
                evidence=[
                    Evidence(file=item.path, detail="Runtime-management evidence.")
                    for item in runtime_evidence
                ],
            )
        )
    vendors: list[VendorRuntimeEvidence] = []
    arcgis_terms = ("arcgispro-py3", "software\\esri\\arcgispro", "arcpy", "arcgis pro")
    if sum(term in joined for term in arcgis_terms) >= 2:
        evidence = [
            Evidence(
                file=item.path, detail="ArcGIS Pro/vendor-Python evidence in deployment support."
            )
            for item, text in corpus
            if any(term in text.lower() for term in arcgis_terms)
        ]
        vendors.append(
            VendorRuntimeEvidence(
                name="ArcGIS Pro",
                description=(
                    "Existing deployment support discovers or clones an ArcGIS Pro-managed "
                    "Python runtime. PDB's uv_managed backend does not reproduce vendor-managed "
                    "Python environments."
                ),
                backend_supported=False,
                required_for_core_launch=None,
                evidence=evidence,
            )
        )
    generic_vendor_items = [
        item
        for item, text in corpus
        if "vendor" in text.lower()
        and re.search(r"(?i)(registry|winreg)", text)
        and re.search(r"(?i)(clone|managed python|vendor python|environment)", text)
    ]
    if generic_vendor_items and not vendors:
        vendors.append(
            VendorRuntimeEvidence(
                name="Vendor-managed Python runtime",
                description=(
                    "Existing deployment support discovers or clones a vendor-managed Python "
                    "runtime. PDB's uv_managed backend does not reproduce vendor-managed Python "
                    "environments."
                ),
                backend_supported=False,
                required_for_core_launch=None,
                evidence=[
                    Evidence(file=item.path, detail="Generic vendor-runtime management evidence.")
                    for item in generic_vendor_items
                ],
            )
        )
    webview_items = [
        item
        for item, text in corpus
        if "webview2" in text.lower() or "edgeupdate\\clients" in text.lower()
    ]
    if webview_items:
        vendors.append(
            VendorRuntimeEvidence(
                name="Microsoft Edge WebView2 Runtime",
                description=(
                    "Existing deployment support detects WebView2 for a browser-backed feature. "
                    "This is external Windows runtime evidence, not proof of a core-launch "
                    "requirement."
                ),
                backend_supported=True,
                required_for_core_launch=False,
                evidence=[
                    Evidence(file=item.path, detail="WebView2 detection evidence.")
                    for item in webview_items
                ],
            )
        )
    findings.sort(key=lambda item: (item.category, item.name.lower()))
    support_dependencies.sort(key=lambda item: item.distribution_name.lower())
    return findings, vendors, support_dependencies
