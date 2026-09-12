"""Static packaging and Python-version metadata inspection."""

from __future__ import annotations

import ast
import configparser
import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from python_deployment_builder.analysis.module_resolution import module_locations
from python_deployment_builder.models import (
    DependencyAssessment,
    EntryPointAssessment,
    Evidence,
    FindingStatus,
    LegacyDependencyGroup,
    PackagingAssessment,
    PythonRequirementAssessment,
)


@dataclass(frozen=True)
class MetadataResult:
    project: PackagingAssessment
    python: PythonRequirementAssessment
    dependencies: list[DependencyAssessment]
    # Assessment inputs rather than persisted packaging fields: an M6.1
    # standalone kit cannot safely represent a uv workspace.
    uv_workspace: bool = False
    uv_workspace_source: bool = False
    uv_workspace_evidence: list[Evidence] = field(default_factory=list)
    setuptools_surface_unresolved: bool = False
    setuptools_surface_evidence: list[Evidence] = field(default_factory=list)
    setuptools_external_packaging_roots: list[str] = field(default_factory=list)
    setuptools_external_packaging_root_evidence: list[Evidence] = field(default_factory=list)
    dynamic_dependency_evidence: list[Evidence] = field(default_factory=list)
    dynamic_entry_point_evidence: list[Evidence] = field(default_factory=list)


@dataclass(frozen=True)
class LiteralModuleAttribute:
    """A literal dynamic setuptools value and the source file that supplied it."""

    value: str
    source_path: str


_SETUP_SURFACE_FIELDS = frozenset(
    {
        "packages",
        "py_modules",
        "package_dir",
        "package_data",
        "exclude_package_data",
        "include_package_data",
    }
)


@dataclass(frozen=True)
class SetupCallInspection:
    """Non-executing setup() inspection with literal-resolution provenance."""

    literal_values: dict[str, Any] = field(default_factory=dict)
    present_keywords: frozenset[str] = frozenset()
    unresolved_keywords: frozenset[str] = frozenset()
    has_kwargs_expansion: bool = False
    parse_failed: bool = False

    @property
    def surface_unresolved(self) -> bool:
        return bool(
            self.parse_failed
            or self.has_kwargs_expansion
            or self.unresolved_keywords & _SETUP_SURFACE_FIELDS
        )

    @property
    def package_selection_present(self) -> bool:
        return self.has_kwargs_expansion or bool(
            self.present_keywords & {"packages", "py_modules"}
        )


# Verified against setuptools 79.0.1's FlatLayoutPackageFinder._EXCLUDE and
# DEFAULT_EXCLUDE.  These defaults are specific to *automatic flat-layout*
# discovery; explicit ``packages.find`` remains a regular finder invocation.
_SETUPTOOLS_79_FLAT_PACKAGE_EXCLUDE_NAMES = (
    "ci",
    "bin",
    "debian",
    "doc",
    "docs",
    "documentation",
    "manpages",
    "news",
    "newsfragments",
    "changelog",
    "test",
    "tests",
    "unit_test",
    "unit_tests",
    "example",
    "examples",
    "scripts",
    "tools",
    "util",
    "utils",
    "python",
    "build",
    "dist",
    "venv",
    "env",
    "requirements",
    "tasks",
    "fabfile",
    "site_scons",
    "benchmark",
    "benchmarks",
    "exercise",
    "exercises",
    "htmlcov",
    "[._]*",
)
_SETUPTOOLS_79_FLAT_PACKAGE_DEFAULT_EXCLUDES = tuple(
    pattern
    for name in _SETUPTOOLS_79_FLAT_PACKAGE_EXCLUDE_NAMES
    for pattern in (name, f"{name}.*")
)

# Verified against setuptools 79.0.1's FlatLayoutModuleFinder.DEFAULT_EXCLUDE.
# Unlike package defaults, these names are top-level module names only.
_SETUPTOOLS_79_FLAT_MODULE_DEFAULT_EXCLUDES = (
    "setup",
    "conftest",
    "test",
    "tests",
    "example",
    "examples",
    "build",
    "toxfile",
    "noxfile",
    "pavement",
    "dodo",
    "tasks",
    "fabfile",
    "[Ss][Cc]onstruct",
    "conanfile",
    "manage",
    "benchmark",
    "benchmarks",
    "exercise",
    "exercises",
    "[._]*",
)

# Verified against setuptools 79.0.1's PackageFinder and
# PEP420PackageFinder.  These are finder-level exclusions, applied before
# user include/exclude filters; unlike flat-layout defaults they cannot be
# re-enabled by an include pattern.  ModuleFinder has no ALWAYS_EXCLUDE set.
_SETUPTOOLS_PACKAGE_FINDER_ALWAYS_EXCLUDES = ("ez_setup", "*__pycache__")


@dataclass(frozen=True)
class PackagingRootInspection:
    """Safety status for a declared physical setuptools packaging root."""

    declared_root: str
    status: str
    normalized_root: str | None = None


def inspect_setuptools_packaging_root(
    repository_root: Path, declared_root: str
) -> PackagingRootInspection:
    """Classify a metadata root without following it outside repository scope.

    PDB's first-party surface and staging boundary is the assessed repository.
    An in-repository missing path is harmless (setuptools simply finds no
    members there), but absolute, escaping, or symlink-rooted declarations
    cannot be treated as absent authoritative surface.
    """

    root = repository_root.resolve()
    declared = Path(declared_root)
    if declared.is_absolute() or PureWindowsPath(declared_root).is_absolute():
        return PackagingRootInspection(declared_root, "UNSAFE")
    try:
        candidate = (repository_root / declared).resolve()
        relative = candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return PackagingRootInspection(declared_root, "UNSAFE")
    # A symlinked root is not a stable source-root representation for staging;
    # in particular, a root symlink could be retargeted after assessment.
    lexical_candidate = repository_root / declared
    if lexical_candidate.is_symlink():
        return PackagingRootInspection(declared_root, "UNSAFE")
    normalized = relative.as_posix() or "."
    return PackagingRootInspection(
        declared_root,
        "SAFE" if lexical_candidate.exists() else "MISSING_SAFE",
        normalized,
    )


def _evidence(root: Path, path: Path, detail: str, line: int | None = None) -> Evidence:
    return Evidence(file=path.relative_to(root).as_posix(), line=line, detail=detail)


def _line_number(path: Path, needle: str) -> int | None:
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
            if needle in line:
                return number
    except OSError:
        return None
    return None


def _dependency(specification: str, group: str, source: Evidence) -> DependencyAssessment | None:
    try:
        requirement = Requirement(specification)
    except InvalidRequirement:
        return None
    constraint = str(requirement.specifier)
    if requirement.url:
        constraint = f"@ {requirement.url}"
    return DependencyAssessment(
        distribution_name=requirement.name,
        declared_constraint=constraint or "unconstrained",
        group=group,
        environment_marker=str(requirement.marker) if requirement.marker else None,
        launch_critical=group == "runtime",
        evidence=[source],
    )


def _entry_point(
    root: Path, pyproject_path: Path, name: str, target: str, group: str
) -> EntryPointAssessment:
    target_lower = f"{name} {target}".lower()
    kind = "gui" if group == "gui-scripts" or "gui" in target_lower else "cli"
    declared_group = "gui_scripts" if group == "gui-scripts" else "console_scripts"
    return EntryPointAssessment(
        name=name,
        target=target,
        kind=kind,
        declared_group=declared_group,
        evidence=[
            _evidence(
                root,
                pyproject_path,
                f"Declared in [project.{group}].",
                _line_number(pyproject_path, f"{name} ="),
            )
        ],
    )


def _requirements_files(root: Path) -> list[Path]:
    return sorted(
        {
            *root.glob("requirements.txt"),
            *root.glob("requirements-*.txt"),
            *root.glob("requirements_*.txt"),
        }
    )


def _parse_requirements_file(root: Path, path: Path, group: str) -> list[DependencyAssessment]:
    dependencies: list[DependencyAssessment] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r", "--requirement", "-c", "--constraint")):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        parsed = _dependency(
            line,
            group,
            _evidence(root, path, "Declared dependency.", line_number),
        )
        if parsed is not None:
            dependencies.append(parsed)
    return dependencies


def _requirements_group(path: Path) -> str:
    if path.name == "requirements.txt":
        return "runtime"
    stem = path.stem
    for prefix in ("requirements-", "requirements_"):
        if stem.startswith(prefix):
            return stem.removeprefix(prefix)
    return stem


def _requirements_includes(root: Path, path: Path) -> list[str]:
    groups: list[str] = []
    for raw_line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith(("-r ", "--requirement ")):
            continue
        raw_target = line.split(maxsplit=1)[1].strip()
        target = (path.parent / raw_target).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            continue
        if target.is_file():
            groups.append(_requirements_group(target))
    return sorted(set(groups))


def _merge_dependencies(items: list[DependencyAssessment]) -> list[DependencyAssessment]:
    merged: dict[tuple[str, str], DependencyAssessment] = {}
    for item in items:
        key = (canonicalize_name(item.distribution_name), item.group)
        if key not in merged:
            merged[key] = item
            continue
        existing = merged[key]
        for evidence in item.evidence:
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
    return sorted(
        merged.values(), key=lambda item: (item.group, canonicalize_name(item.distribution_name))
    )


def _multiline_values(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _merge_package_data_declarations(
    destination: dict[str, list[str]],
    evidence_by_package: dict[str, dict[str, Evidence]],
    declarations: dict[str, list[str]],
    evidence: Evidence,
) -> None:
    """Merge literal package-data declarations while retaining their source evidence."""

    for package, patterns in declarations.items():
        existing = destination.setdefault(package, [])
        sources = evidence_by_package.setdefault(package, {})
        for pattern in patterns:
            if pattern not in existing:
                existing.append(pattern)
            sources.setdefault(pattern, evidence)


def _package_data_mapping(
    value: Any, *, empty_key_is_wildcard: bool = False
) -> dict[str, list[str]]:
    """Read the supported literal setuptools package-data mapping shape."""

    declarations = _literal_package_data_mapping(value)
    if declarations is None:
        return {}
    return {
        "*" if empty_key_is_wildcard and package == "" else package: patterns
        for package, patterns in declarations.items()
    }


def _literal_string_sequence(value: Any) -> list[str] | None:
    """Return a fully literal setuptools string sequence without coercion."""

    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def _literal_package_data_mapping(value: Any) -> dict[str, list[str]] | None:
    """Return a fully literal package-data mapping or mark it unresolved."""

    if not isinstance(value, dict):
        return None
    declarations: dict[str, list[str]] = {}
    for package, patterns in value.items():
        sequence = _literal_string_sequence(patterns)
        if not isinstance(package, str) or sequence is None:
            return None
        declarations[package] = sequence
    return declarations


def _string_list(value: Any, *, default: list[str] | None = None) -> list[str]:
    """Return the supported TOML/list-or-string metadata shape without coercion."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return list(default or [])


def _discover_setuptools_packages(
    root: Path,
    search_roots: list[str],
    package_directories: dict[str, str],
    include: list[str],
    exclude: list[str],
    namespaces: bool,
) -> list[str]:
    """Statically resolve the bounded setuptools ``find`` package surface.

    This is filesystem-only metadata interpretation: it never imports modules,
    follows package symlinks, or includes paths outside the assessed repository.
    """

    resolved_root = root.resolve()
    discovered: set[str] = set()
    includes = include or ["*"]
    for configured_root in search_roots:
        root_inspection = inspect_setuptools_packaging_root(root, configured_root)
        if root_inspection.status == "UNSAFE" or root_inspection.normalized_root is None:
            continue
        candidate_root = root / root_inspection.normalized_root
        if candidate_root.is_symlink() or not candidate_root.is_dir():
            continue
        try:
            candidate_root.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        named_prefixes = [
            name
            for name, directory in package_directories.items()
            if name
            and (root / directory).resolve() == candidate_root.resolve()
        ]
        prefix = max(named_prefixes, key=lambda name: len(name.split(".")), default="")
        for directory in sorted(candidate_root.rglob("*")):
            if directory.is_symlink() or not directory.is_dir():
                continue
            try:
                relative = directory.resolve().relative_to(candidate_root.resolve())
            except ValueError:
                continue
            if not relative.parts or any(part == "__pycache__" for part in relative.parts):
                continue
            parts = (*prefix.split("."), *relative.parts) if prefix else relative.parts
            if not all(part.isidentifier() for part in parts):
                continue
            if not namespaces:
                # ``find_packages()`` cannot discover a child through a
                # non-package parent.  Checking only this directory's
                # initializer would incorrectly turn ``container/sub`` into
                # ``container.sub`` when ``container`` is not a package.
                package_directories_in_path = [
                    candidate_root / Path(*relative.parts[: index + 1])
                    for index in range(len(relative.parts))
                ]
                if any(
                    initializer.is_symlink() or not initializer.is_file()
                    for initializer in (
                        item / "__init__.py" for item in package_directories_in_path
                    )
                ):
                    continue
            package = ".".join(parts)
            # Setuptools' PackageFinder and PEP420PackageFinder compose these
            # unconditional exclusions before user include/exclude filters.
            # User ``include = [\"ez_setup*\"]`` cannot re-enable them.
            if any(
                fnmatch.fnmatchcase(package, pattern)
                for pattern in _SETUPTOOLS_PACKAGE_FINDER_ALWAYS_EXCLUDES
            ):
                continue
            if any(fnmatch.fnmatchcase(package, pattern) for pattern in includes) and not any(
                fnmatch.fnmatchcase(package, pattern) for pattern in exclude
            ):
                discovered.add(package)
    return sorted(discovered)


def _discover_named_setuptools_packages(
    root: Path, package_directories: dict[str, str]
) -> list[str] | None:
    """Mirror setuptools 79 explicit-layout roots plus PEP420 descendants.

    Discovery supplies installed prefixes; module_locations remains responsible
    for exact/longest-parent physical locations. A missing declared root is not
    permission to fall back to a different automatic layout.
    """

    packages: set[str] = set()
    for package, directory in package_directories.items():
        if not package:
            continue
        locations = module_locations(root, package, [], package_directories)
        if len(locations) != 1 or not locations[0].is_dir():
            return None
        packages.add(package)
        # The finder exclusions apply to names relative to this root, before
        # prefixing, exactly as setuptools' _find_packages_within does.
        packages.update(
            f"{package}.{descendant}"
            for descendant in _discover_setuptools_packages(
                root, [directory], {}, ["*"], [], True
            )
        )
    return sorted(packages)


def _discover_setuptools_py_modules(
    root: Path,
    search_roots: list[str],
    *,
    excluded_modules: list[str] | None = None,
) -> list[str]:
    """Resolve safe top-level modules for bounded setuptools auto-discovery.

    Setuptools discovers standalone modules from the configured source root,
    not by recursively treating every Python file as a module.  This shares
    the same filesystem-only safety boundary as package discovery.
    """

    resolved_root = root.resolve()
    discovered: set[str] = set()
    exclusions = excluded_modules or []
    for configured_root in search_roots:
        root_inspection = inspect_setuptools_packaging_root(root, configured_root)
        if root_inspection.status == "UNSAFE" or root_inspection.normalized_root is None:
            continue
        candidate_root = root / root_inspection.normalized_root
        if candidate_root.is_symlink() or not candidate_root.is_dir():
            continue
        try:
            candidate_root.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        for candidate in sorted(candidate_root.glob("*.py")):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                candidate.resolve().relative_to(candidate_root.resolve())
            except ValueError:
                continue
            module = candidate.stem
            if (
                module == "__init__"
                or not module.isidentifier()
                or any(fnmatch.fnmatchcase(module, pattern) for pattern in exclusions)
            ):
                continue
            discovered.add(module)
    return sorted(discovered)


def inspect_setup_call(path: Path) -> SetupCallInspection:
    """Inspect setup() literals without executing or evaluating target code."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return SetupCallInspection(parse_failed=True)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name != "setup":
            continue
        values: dict[str, Any] = {}
        present: set[str] = set()
        unresolved: set[str] = set()
        has_kwargs_expansion = False
        for keyword in node.keywords:
            if keyword.arg is None:
                has_kwargs_expansion = True
                continue
            present.add(keyword.arg)
            try:
                values[keyword.arg] = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                if keyword.arg in _SETUP_SURFACE_FIELDS:
                    unresolved.add(keyword.arg)
            else:
                if keyword.arg in {"packages", "py_modules"} and (
                    _literal_string_sequence(values[keyword.arg]) is None
                ):
                    # A malformed literal selection is no more authoritative
                    # than a dynamic one. Do not retain a string subset and
                    # silently claim a complete setuptools surface.
                    unresolved.add(keyword.arg)
                elif keyword.arg in {"package_data", "exclude_package_data"} and (
                    _literal_package_data_mapping(values[keyword.arg]) is None
                ):
                    unresolved.add(keyword.arg)
        return SetupCallInspection(
            literal_values=values,
            present_keywords=frozenset(present),
            unresolved_keywords=frozenset(unresolved),
            has_kwargs_expansion=has_kwargs_expansion,
        )
    return SetupCallInspection()


def setup_py_surface_resolved(root: Path) -> bool:
    """Whether a local setup.py leaves PDB's modeled surface statically known."""

    path = root / "setup.py"
    return not path.is_file() or not inspect_setup_call(path).surface_unresolved


def setuptools_packaging_roots_safe(root: Path) -> bool:
    """Whether all declared authoritative setuptools roots stay in scope."""

    return not inspect_metadata(root).setuptools_external_packaging_roots


def setuptools_packaging_surface_resolved(root: Path) -> bool:
    """Whether a local setuptools project has a statically authoritative surface."""

    metadata = inspect_metadata(root)
    return (
        not metadata.setuptools_surface_unresolved
        and not metadata.setuptools_external_packaging_roots
    )


def _literal_module_attribute(
    root: Path,
    attribute: str,
    *,
    package_directories: dict[str, str] | None = None,
    source_roots: list[str] | None = None,
) -> LiteralModuleAttribute | None:
    """Resolve a setuptools dynamic version attr only when it is a string literal."""

    try:
        module_name, attribute_name = attribute.rsplit(".", 1)
    except ValueError:
        return None
    if not all(part.isidentifier() for part in module_name.split(".")):
        return None
    module_parts = module_name.split(".")
    package_directories = package_directories or {}
    source_roots = source_roots or []
    candidate_bases: list[Path] = []
    named_mappings = [
        name
        for name in package_directories
        if name and (module_name == name or module_name.startswith(f"{name}."))
    ]
    if named_mappings:
        mapping = max(named_mappings, key=lambda name: len(name.split(".")))
        inspection = inspect_setuptools_packaging_root(root, package_directories[mapping])
        if inspection.status != "UNSAFE" and inspection.normalized_root is not None:
            remainder = module_parts[len(mapping.split(".")) :]
            candidate_bases.append(root / inspection.normalized_root / Path(*remainder))
    elif "" in package_directories:
        inspection = inspect_setuptools_packaging_root(root, package_directories[""])
        if inspection.status != "UNSAFE" and inspection.normalized_root is not None:
            candidate_bases.append(root / inspection.normalized_root / Path(*module_parts))
    else:
        for source_root in [*source_roots, "src", "."]:
            inspection = inspect_setuptools_packaging_root(root, source_root)
            if inspection.status != "UNSAFE" and inspection.normalized_root is not None:
                candidate_bases.append(root / inspection.normalized_root / Path(*module_parts))
    candidates: list[Path] = []
    for base in candidate_bases:
        candidates.extend((base.with_suffix(".py"), base / "__init__.py"))
    seen_candidates: set[Path] = set()
    resolutions: list[LiteralModuleAttribute] = []
    for path in candidates:
        if path in seen_candidates:
            continue
        seen_candidates.add(path)
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        resolved_values: list[str] = []
        for node in tree.body:
            value_node: ast.expr | None = None
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == attribute_name
                    for target in node.targets
                )
            ) or (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == attribute_name
            ):
                value_node = node.value
            if value_node is not None:
                try:
                    value = ast.literal_eval(value_node)
                except (ValueError, TypeError):
                    resolved_values = []
                    break
                if not isinstance(value, str) or not value.strip():
                    resolved_values = []
                    break
                resolved_values.append(value)
        if len(resolved_values) == 1:
            try:
                source_path = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                return None
            resolutions.append(
                LiteralModuleAttribute(value=resolved_values[0], source_path=source_path)
            )
    # Multiple configured roots must not let declaration order choose the
    # authoritative version module.  One literal source is the bounded model.
    return resolutions[0] if len(resolutions) == 1 else None


def _documented_python_versions(root: Path) -> tuple[list[str], list[Evidence]]:
    versions: set[str] = set()
    evidence: list[Evidence] = []
    for filename in ("README.md", "AGENTS.md", "CONTRIBUTING.md"):
        path = root / filename
        if not path.is_file():
            continue
        for number, line in enumerate(
            path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), start=1
        ):
            for match in re.finditer(r"(?i)Python\s+(3\.\d+)(?:\+|\s|$)", line):
                versions.add(match.group(1))
                evidence.append(_evidence(root, path, "Documented Python version.", number))
    return sorted(versions), evidence


def inspect_metadata(root: Path) -> MetadataResult:
    """Inspect standardized metadata without importing or executing the project."""

    metadata_files: list[str] = []
    dependencies: list[DependencyAssessment] = []
    optional_groups: dict[str, list[str]] = {}
    entry_points: list[EntryPointAssessment] = []
    legacy_groups: list[LegacyDependencyGroup] = []
    distribution_name: str | None = None
    project_version: str | None = None
    build_backend: str | None = None
    requires_python: str | None = None
    ruff_target: str | None = None
    source_roots: list[str] = []
    packages: list[str] = []
    py_modules: list[str] = []
    package_directories: dict[str, str] = {}
    package_data: dict[str, list[str]] = {}
    exclude_package_data: dict[str, list[str]] = {}
    package_data_evidence: dict[str, dict[str, Evidence]] = {}
    exclude_package_data_evidence: dict[str, dict[str, Evidence]] = {}
    layout = "unknown"
    python_evidence: list[Evidence] = []
    package_discovery_rules: list[tuple[list[str], list[str], list[str], bool]] = []
    automatic_setuptools_root: str | None = None
    automatic_setuptools_src_layout = False
    automatic_setuptools_flat_surface_ambiguous = False
    setuptools_package_selection_configured = False
    setuptools_surface_unresolved = False
    setuptools_surface_evidence: list[Evidence] = []
    setuptools_external_packaging_roots: list[str] = []
    setuptools_external_packaging_root_evidence: list[Evidence] = []
    pyproject_controls_include_package_data = False
    pyproject_include_package_data: bool | None = None
    pyproject_include_package_data_invalid = False
    setup_cfg_include_package_data: bool | None = False
    setup_py_include_package_data: bool | None = False
    setuptools_file_finder_requirements: list[str] = []
    uv_workspace = False
    uv_workspace_source = False
    uv_workspace_evidence: list[Evidence] = []
    project_dependencies_static_authoritative = False
    project_python_static_authoritative = False
    static_entry_point_groups: set[str] = set()
    dynamic_dependency_evidence: list[Evidence] = []
    dynamic_entry_point_evidence: list[Evidence] = []

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        metadata_files.append("pyproject.toml")
        with pyproject_path.open("rb") as handle:
            document: dict[str, Any] = tomllib.load(handle)
        project_table_present = isinstance(document.get("project"), dict)
        project = document["project"] if project_table_present else {}
        project_dynamic = project.get("dynamic", [])
        if not isinstance(project_dynamic, list) or any(
            not isinstance(value, str) for value in project_dynamic
        ):
            raise ValueError("[project].dynamic must be a list of field names.")
        project_dependencies_present = "dependencies" in project
        project_dependencies_dynamic = "dependencies" in project_dynamic
        project_dependencies_static_authoritative = (
            project_table_present and not project_dependencies_dynamic
        )
        project_python_static_authoritative = (
            project_table_present and "requires-python" not in project_dynamic
        )
        if project_dependencies_present and (
            not isinstance(project["dependencies"], list)
            or any(not isinstance(value, str) for value in project["dependencies"])
        ):
            raise ValueError("[project].dependencies must be a list of requirement strings.")
        if project_dependencies_dynamic:
            dynamic_dependency_evidence.append(
                _evidence(
                    root,
                    pyproject_path,
                    "[project].dynamic includes dependencies; the static list is not a "
                    "complete dependency contract. M6.1 does not prove backend additions, "
                    "and setuptools 79.0.1 rejects simultaneous static/dynamic dependencies.",
                    _line_number(pyproject_path, "dynamic"),
                )
            )
        static_entry_point_groups = {
            legacy_group
            for group, legacy_group in (
                ("scripts", "console_scripts"), ("gui-scripts", "gui_scripts")
            )
            if project_table_present and group not in project_dynamic
        }
        for group in ("scripts", "gui-scripts"):
            if group in project_dynamic:
                dynamic_entry_point_evidence.append(
                    _evidence(
                        root,
                        pyproject_path,
                        f"[project].{group} is dynamic; M6.1 cannot prove the backend's "
                        "complete launcher group. Pinned setuptools rejects simultaneous "
                        "static/dynamic groups and may omit legacy-only launchers.",
                        _line_number(pyproject_path, "dynamic"),
                    )
                )
        build_system = (
            document.get("build-system") if isinstance(document.get("build-system"), dict) else {}
        )
        for specification in build_system.get("requires", []):
            if not isinstance(specification, str):
                continue
            try:
                build_requirement = Requirement(specification)
            except InvalidRequirement:
                continue
            if canonicalize_name(build_requirement.name) == "setuptools-scm":
                setuptools_file_finder_requirements.append(specification)
        distribution_name = project.get("name") if isinstance(project.get("name"), str) else None
        project_version = (
            project.get("version") if isinstance(project.get("version"), str) else None
        )
        tool = document.get("tool") if isinstance(document.get("tool"), dict) else {}
        setuptools = tool.get("setuptools") if isinstance(tool.get("setuptools"), dict) else {}
        dynamic_package_directories = (
            {
                name: path
                for name, path in setuptools.get("package-dir", {}).items()
                if isinstance(name, str) and isinstance(path, str)
            }
            if isinstance(setuptools.get("package-dir"), dict)
            else {}
        )
        dynamic_package_find = (
            setuptools.get("packages", {}).get("find", {})
            if isinstance(setuptools.get("packages"), dict)
            else {}
        )
        dynamic_source_roots = (
            _string_list(dynamic_package_find.get("where"), default=["."])
            if isinstance(dynamic_package_find, dict)
            else []
        )
        if not dynamic_source_roots and isinstance(dynamic_package_directories.get(""), str):
            dynamic_source_roots = [dynamic_package_directories[""]]
        if project_version is None and "version" in project.get("dynamic", []):
            dynamic = (
                setuptools.get("dynamic") if isinstance(setuptools.get("dynamic"), dict) else {}
            )
            version_rule = dynamic.get("version")
            version_attr = version_rule.get("attr") if isinstance(version_rule, dict) else None
            if isinstance(version_attr, str):
                resolved_version = _literal_module_attribute(
                    root,
                    version_attr,
                    package_directories=dynamic_package_directories,
                    source_roots=dynamic_source_roots,
                )
                if resolved_version is not None:
                    project_version = resolved_version.value
                    # metadata_files is also the model-derived provenance input list.
                    # A literal dynamic-version module is parsed to establish the
                    # authoritative project version even when package mode does not
                    # stage the source file.
                    metadata_files.append(resolved_version.source_path)
        requires_python = (
            project.get("requires-python")
            if isinstance(project.get("requires-python"), str)
            else None
        )
        build_backend = (
            build_system.get("build-backend")
            if isinstance(build_system.get("build-backend"), str)
            else None
        )
        pyproject_controls_include_package_data = bool(
            (
                isinstance(build_backend, str)
                and build_backend.startswith("setuptools.")
                and isinstance(document.get("project"), dict)
            )
            or setuptools
        )
        if pyproject_controls_include_package_data:
            configured_include_package_data = setuptools.get(
                "include-package-data", True
            )
            if isinstance(configured_include_package_data, bool):
                pyproject_include_package_data = configured_include_package_data
            else:
                pyproject_include_package_data_invalid = True
        if requires_python:
            python_evidence.append(
                _evidence(
                    root,
                    pyproject_path,
                    "[project].requires-python",
                    _line_number(pyproject_path, "requires-python"),
                )
            )
        runtime_specs = project.get("dependencies", [])
        if isinstance(runtime_specs, list):
            for specification in runtime_specs:
                if isinstance(specification, str):
                    parsed = _dependency(
                        specification,
                        "runtime",
                        _evidence(
                            root,
                            pyproject_path,
                            "Declared in [project].dependencies.",
                            _line_number(pyproject_path, f'"{specification}"'),
                        ),
                    )
                    if parsed:
                        dependencies.append(parsed)
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in optional.items():
                if not isinstance(group, str) or not isinstance(values, list):
                    continue
                optional_groups[group] = [value for value in values if isinstance(value, str)]
                for specification in optional_groups[group]:
                    parsed = _dependency(
                        specification,
                        group,
                        _evidence(
                            root,
                            pyproject_path,
                            f"Declared in [project.optional-dependencies].{group}.",
                            _line_number(pyproject_path, f'"{specification}"'),
                        ),
                    )
                    if parsed:
                        dependencies.append(parsed)
        for group in ("scripts", "gui-scripts"):
            values = project.get(group, {})
            if isinstance(values, dict):
                entry_points.extend(
                    _entry_point(root, pyproject_path, name, target, group)
                    for name, target in values.items()
                    if isinstance(name, str) and isinstance(target, str)
                )
        uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
        uv_workspace = isinstance(uv.get("workspace"), dict)
        uv_sources = uv.get("sources") if isinstance(uv.get("sources"), dict) else {}
        uv_workspace_source = any(
            isinstance(source, dict) and source.get("workspace") is True
            for source in uv_sources.values()
        )
        if uv_workspace or uv_workspace_source:
            table = "[tool.uv.workspace]" if uv_workspace else "[tool.uv.sources]"
            uv_workspace_evidence.append(
                _evidence(
                    root,
                    pyproject_path,
                    f"Declared in {table}.",
                    _line_number(pyproject_path, table.removeprefix("[").removesuffix("]")),
                )
            )
        poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
        if poetry and not project:
            distribution_name = (
                poetry.get("name") if isinstance(poetry.get("name"), str) else distribution_name
            )
            project_version = (
                poetry.get("version") if isinstance(poetry.get("version"), str) else project_version
            )
            poetry_dependencies = (
                poetry.get("dependencies") if isinstance(poetry.get("dependencies"), dict) else {}
            )
            for name, constraint_value in poetry_dependencies.items():
                if not isinstance(name, str):
                    continue
                if canonicalize_name(name) == "python":
                    if isinstance(constraint_value, str):
                        requires_python = constraint_value
                    continue
                constraint = (
                    constraint_value
                    if isinstance(constraint_value, str)
                    else str(constraint_value.get("version", "unconstrained"))
                    if isinstance(constraint_value, dict)
                    else "unconstrained"
                )
                dependencies.append(
                    DependencyAssessment(
                        distribution_name=name,
                        declared_constraint=constraint,
                        group="runtime",
                        launch_critical=True,
                        evidence=[
                            _evidence(
                                root,
                                pyproject_path,
                                "Declared in [tool.poetry.dependencies].",
                                _line_number(pyproject_path, name),
                            )
                        ],
                    )
                )
            poetry_scripts = (
                poetry.get("scripts") if isinstance(poetry.get("scripts"), dict) else {}
            )
            for name, target in poetry_scripts.items():
                if isinstance(name, str) and isinstance(target, str):
                    # The supported string form maps to Poetry's standard
                    # console-script entry-point behavior.
                    entry_points.append(_entry_point(root, pyproject_path, name, target, "scripts"))
        if build_backend is None and setuptools:
            # A project that supplies setuptools' own pyproject configuration
            # but omits [build-system] follows the conventional setuptools
            # legacy PEP 517 fallback.  Record that supported backend explicitly
            # so the same authoritative surface resolver serves this form as
            # explicit setuptools.build_meta projects.
            build_backend = "setuptools.build_meta:__legacy__"
        configured_packages = setuptools.get("packages")
        if "packages" in setuptools or "py-modules" in setuptools:
            setuptools_package_selection_configured = True
        if isinstance(configured_packages, list):
            packages = [value for value in configured_packages if isinstance(value, str)]
        py_modules = _string_list(setuptools.get("py-modules"))
        configured_package_dirs = setuptools.get("package-dir")
        if isinstance(configured_package_dirs, dict):
            package_directories = {
                name: path
                for name, path in configured_package_dirs.items()
                if isinstance(name, str) and isinstance(path, str)
            }
            if isinstance(package_directories.get(""), str):
                source_roots = source_roots or [package_directories[""]]
        configured_package_data = setuptools.get("package-data")
        _merge_package_data_declarations(
            package_data,
            package_data_evidence,
            _package_data_mapping(configured_package_data),
            _evidence(
                root,
                pyproject_path,
                "Authoritative setuptools package-data declaration in "
                "[tool.setuptools.package-data].",
                _line_number(pyproject_path, "package-data"),
            ),
        )
        _merge_package_data_declarations(
            exclude_package_data,
            exclude_package_data_evidence,
            _package_data_mapping(setuptools.get("exclude-package-data")),
            _evidence(
                root,
                pyproject_path,
                "Authoritative setuptools exclude-package-data declaration in "
                "[tool.setuptools.exclude-package-data].",
                _line_number(pyproject_path, "exclude-package-data"),
            ),
        )
        package_find = (
            setuptools.get("packages", {}).get("find", {})
            if isinstance(setuptools.get("packages"), dict)
            else {}
        )
        if isinstance(setuptools.get("packages"), dict) and isinstance(package_find, dict):
            configured_where = _string_list(package_find.get("where"), default=["."])
            source_roots = configured_where
            package_discovery_rules.append(
                (
                    configured_where,
                    _string_list(package_find.get("include"), default=["*"]),
                    _string_list(package_find.get("exclude")),
                    package_find.get("namespaces", True) is not False,
                )
            )
        ruff = tool.get("ruff") if isinstance(tool.get("ruff"), dict) else {}
        ruff_target = (
            ruff.get("target-version") if isinstance(ruff.get("target-version"), str) else None
        )
        if ruff_target:
            python_evidence.append(
                _evidence(
                    root,
                    pyproject_path,
                    "Ruff target-version.",
                    _line_number(pyproject_path, "target-version"),
                )
            )

    setup_cfg_path = root / "setup.cfg"
    if setup_cfg_path.is_file():
        metadata_files.append("setup.cfg")
        parser = configparser.ConfigParser()
        parser.read(setup_cfg_path, encoding="utf-8")
        # Standard setup.cfg options are case-insensitive. Package-data option names
        # are Python package identifiers, so inspect that one identifier-keyed section
        # separately without changing the ordinary metadata/options parser semantics.
        package_data_parser = configparser.ConfigParser()
        package_data_parser.optionxform = str
        package_data_parser.read(setup_cfg_path, encoding="utf-8")
        if parser.has_option("options", "include_package_data"):
            try:
                setup_cfg_include_package_data = parser.getboolean(
                    "options", "include_package_data"
                )
            except ValueError:
                setup_cfg_include_package_data = None
        if distribution_name is None:
            distribution_name = parser.get("metadata", "name", fallback=None)
            project_version = parser.get("metadata", "version", fallback=None)
            if not project_python_static_authoritative:
                requires_python = parser.get("options", "python_requires", fallback=None)
        # Under an existing [project], omitted non-dynamic fields are empty too.
        # Without [project], legacy metadata remains authoritative.
        install_requires = (
            ""
            if project_dependencies_static_authoritative
            else parser.get("options", "install_requires", fallback="")
        )
        for specification in _multiline_values(install_requires):
            parsed = _dependency(
                specification,
                "runtime",
                _evidence(
                    root,
                    setup_cfg_path,
                    "Declared in [options].install_requires.",
                    _line_number(setup_cfg_path, specification),
                ),
            )
            if parsed:
                dependencies.append(parsed)
        if parser.has_section("options.entry_points"):
            for group in ("console_scripts", "gui_scripts"):
                if group in static_entry_point_groups:
                    continue
                for specification in _multiline_values(
                    parser.get("options.entry_points", group, fallback="")
                ):
                    if "=" not in specification:
                        continue
                    name, target = (part.strip() for part in specification.split("=", 1))
                    entry_points.append(
                        EntryPointAssessment(
                            name=name,
                            target=target,
                            kind="gui" if group == "gui_scripts" else "cli",
                            declared_group=group,
                            evidence=[
                                _evidence(
                                    root,
                                    setup_cfg_path,
                                    f"Declared in [options.entry_points].{group}.",
                                    _line_number(setup_cfg_path, specification),
                                )
                            ],
                        )
                    )
        configured_where = parser.get("options.packages.find", "where", fallback="").strip()
        if configured_where and not source_roots:
            source_roots = [configured_where]
        configured_packages = parser.get("options", "packages", fallback="").strip()
        if configured_packages or parser.has_option("options", "py_modules"):
            setuptools_package_selection_configured = True
        if (
            configured_packages
            and configured_packages not in {"find:", "find_namespace:"}
            and not packages
        ):
            packages = _multiline_values(configured_packages)
        configured_package_dir = parser.get("options", "package_dir", fallback="")
        if configured_package_dir:
            setup_cfg_directories = {
                name.strip(): path.strip()
                for value in _multiline_values(configured_package_dir)
                if "=" in value
                for name, path in [value.split("=", 1)]
                if path.strip()
            }
            package_directories.update(setup_cfg_directories)
            if isinstance(package_directories.get(""), str):
                source_roots = source_roots or [package_directories[""]]
        if not py_modules:
            py_modules = _multiline_values(parser.get("options", "py_modules", fallback=""))
        if configured_packages in {"find:", "find_namespace:"}:
            discovery_roots = _multiline_values(configured_where)
            if not discovery_roots:
                discovery_roots = [package_directories.get("", ".")]
            package_discovery_rules.append(
                (
                    discovery_roots,
                    _multiline_values(
                        parser.get("options.packages.find", "include", fallback="")
                    )
                    or ["*"],
                    _multiline_values(
                        parser.get("options.packages.find", "exclude", fallback="")
                    ),
                    configured_packages == "find_namespace:",
                )
            )
        if package_data_parser.has_section("options.package_data"):
            for package, value in package_data_parser.items("options.package_data"):
                patterns = _multiline_values(value)
                if not patterns:
                    continue
                _merge_package_data_declarations(
                    package_data,
                    package_data_evidence,
                    {package: patterns},
                    _evidence(
                        root,
                        setup_cfg_path,
                        "Authoritative setuptools package-data declaration in "
                        "[options.package_data].",
                        _line_number(setup_cfg_path, package),
                    ),
                )
        if package_data_parser.has_section("options.exclude_package_data"):
            for package, value in package_data_parser.items("options.exclude_package_data"):
                patterns = _multiline_values(value)
                if not patterns:
                    continue
                _merge_package_data_declarations(
                    exclude_package_data,
                    exclude_package_data_evidence,
                    {package: patterns},
                    _evidence(
                        root,
                        setup_cfg_path,
                        "Authoritative setuptools exclude-package-data declaration in "
                        "[options.exclude_package_data].",
                        _line_number(setup_cfg_path, package),
                    ),
                )

    setup_py_path = root / "setup.py"
    if setup_py_path.is_file():
        metadata_files.append("setup.py")
        setup_inspection = inspect_setup_call(setup_py_path)
        setup_values = setup_inspection.literal_values
        if setup_inspection.has_kwargs_expansion:
            setup_py_include_package_data = None
        elif "include_package_data" in setup_inspection.present_keywords:
            configured_include_package_data = setup_values.get("include_package_data")
            setup_py_include_package_data = (
                configured_include_package_data
                if isinstance(configured_include_package_data, bool)
                else None
            )
        setuptools_package_selection_configured = (
            setuptools_package_selection_configured
            or setup_inspection.package_selection_present
        )
        setup_unresolved_fields = set(
            setup_inspection.unresolved_keywords & _SETUP_SURFACE_FIELDS
        )
        if pyproject_controls_include_package_data:
            # Setuptools 79.0.1's pyproject configuration is authoritative for
            # include-package-data. A literal legacy setup() value does not
            # override an explicit pyproject value.
            setup_unresolved_fields.discard("include_package_data")
        setup_surface_unresolved = bool(
            setup_inspection.parse_failed
            or setup_inspection.has_kwargs_expansion
            or setup_unresolved_fields
        )
        setuptools_surface_unresolved = (
            setuptools_surface_unresolved or setup_surface_unresolved
        )
        if setup_surface_unresolved:
            unresolved = sorted(setup_unresolved_fields)
            detail = (
                "setup() expands **kwargs, so modeled packaging-surface fields cannot be "
                "statically established."
                if setup_inspection.has_kwargs_expansion
                else "setup() has nonliteral packaging-surface field(s): "
                + ", ".join(unresolved or ["setup.py parse failure"])
            )
            setuptools_surface_evidence.append(
                _evidence(
                    root,
                    setup_py_path,
                    detail,
                    _line_number(setup_py_path, "setup("),
                )
            )
        literal_packages = _literal_string_sequence(setup_values.get("packages"))
        if literal_packages is not None and not packages:
            packages = literal_packages
        literal_py_modules = _literal_string_sequence(setup_values.get("py_modules"))
        if literal_py_modules is not None and not py_modules:
            py_modules = literal_py_modules
        if distribution_name is None and isinstance(setup_values.get("name"), str):
            distribution_name = setup_values["name"]
        if project_version is None and isinstance(setup_values.get("version"), str):
            project_version = setup_values["version"]
        if (
            not project_python_static_authoritative
            and requires_python is None
            and isinstance(setup_values.get("python_requires"), str)
        ):
            requires_python = setup_values["python_requires"]
        legacy_runtime_specs = (
            []
            if project_dependencies_static_authoritative
            else _literal_string_sequence(setup_values.get("install_requires")) or []
        )
        for specification in legacy_runtime_specs:
            parsed = _dependency(
                specification,
                "runtime",
                _evidence(
                    root,
                    setup_py_path,
                    "Literal setup(install_requires=...) value; setup.py was not executed.",
                    _line_number(setup_py_path, specification),
                ),
            )
            if parsed:
                dependencies.append(parsed)
        setup_entry_points = setup_values.get("entry_points", {})
        if isinstance(setup_entry_points, dict):
            for group in ("console_scripts", "gui_scripts"):
                if group in static_entry_point_groups:
                    continue
                values = _literal_string_sequence(setup_entry_points.get(group))
                if values is None:
                    continue
                for specification in values:
                    if not isinstance(specification, str) or "=" not in specification:
                        continue
                    name, target = (part.strip() for part in specification.split("=", 1))
                    entry_points.append(
                        EntryPointAssessment(
                            name=name,
                            target=target,
                            kind="gui" if group == "gui_scripts" else "cli",
                            declared_group=group,
                            evidence=[
                                _evidence(
                                    root,
                                    setup_py_path,
                                    "Literal setup(entry_points=...) value; setup.py was not "
                                    "executed.",
                                    _line_number(setup_py_path, specification),
                                )
                            ],
                        )
                    )
        package_dir = setup_values.get("package_dir")
        if isinstance(package_dir, dict):
            setup_directories = {
                name: path
                for name, path in package_dir.items()
                if isinstance(name, str) and isinstance(path, str)
            }
            package_directories.update(setup_directories)
            if isinstance(package_directories.get(""), str):
                source_roots = source_roots or [package_directories[""]]
        literal_package_data = _package_data_mapping(
            setup_values.get("package_data"), empty_key_is_wildcard=True
        )
        literal_exclude_package_data = _package_data_mapping(
            setup_values.get("exclude_package_data"), empty_key_is_wildcard=True
        )
        _merge_package_data_declarations(
            package_data,
            package_data_evidence,
            literal_package_data,
            _evidence(
                root,
                setup_py_path,
                "Literal setup(package_data=...) value; setup.py was not executed.",
                _line_number(setup_py_path, "package_data"),
            ),
        )
        _merge_package_data_declarations(
            exclude_package_data,
            exclude_package_data_evidence,
            literal_exclude_package_data,
            _evidence(
                root,
                setup_py_path,
                "Literal setup(exclude_package_data=...) value; setup.py was not executed.",
                _line_number(setup_py_path, "exclude_package_data"),
            ),
        )

    manifest_path = root / "MANIFEST.in"
    modeled_setuptools = bool(
        isinstance(build_backend, str) and build_backend.startswith("setuptools.")
    ) or (build_backend is None and (setup_cfg_path.is_file() or setup_py_path.is_file()))
    effective_include_package_data: bool | None = False
    include_package_data_evidence_path: Path | None = None
    if modeled_setuptools:
        if pyproject_controls_include_package_data:
            effective_include_package_data = (
                None
                if pyproject_include_package_data_invalid
                else pyproject_include_package_data
            )
            include_package_data_evidence_path = pyproject_path
        else:
            legacy_values = [
                value
                for path, value in (
                    (setup_cfg_path, setup_cfg_include_package_data),
                    (setup_py_path, setup_py_include_package_data),
                )
                if path.is_file()
            ]
            if any(value is True for value in legacy_values):
                # Setuptools 79.0.1 keeps the mechanism enabled when either
                # legacy configuration source explicitly enables it.
                effective_include_package_data = True
            elif any(value is None for value in legacy_values):
                effective_include_package_data = None
            else:
                effective_include_package_data = False
            include_package_data_evidence_path = next(
                (path for path in (setup_py_path, setup_cfg_path) if path.is_file()),
                None,
            )
    if modeled_setuptools and effective_include_package_data is None:
        setuptools_surface_unresolved = True
        evidence_path = include_package_data_evidence_path or pyproject_path
        setuptools_surface_evidence.append(
            _evidence(
                root,
                evidence_path,
                "Setuptools include_package_data is present but cannot be resolved to a "
                "literal boolean without executing project configuration.",
                _line_number(evidence_path, "include_package_data"),
            )
        )
    if (
        modeled_setuptools
        and manifest_path.is_file()
        and effective_include_package_data is not False
    ):
        # MANIFEST.in is authoritative build metadata only while setuptools'
        # file-list package-data mechanism can affect the wheel. It remains a
        # provenance input, never an inferred runtime resource or staged file.
        metadata_files.append("MANIFEST.in")
        setuptools_surface_unresolved = True
        state = "True" if effective_include_package_data is True else "unresolved"
        setuptools_surface_evidence.append(
            _evidence(
                root,
                manifest_path,
                "MANIFEST.in may contribute package data through effective "
                f"include_package_data={state}; M6.1 does not interpret setuptools "
                "manifest/file-list semantics.",
                1,
            )
        )
    if (
        modeled_setuptools
        and effective_include_package_data is not False
        and setuptools_file_finder_requirements
    ):
        # setuptools-scm registers a setuptools file-finder hook that can add
        # version-controlled package files without explicit package_data.
        # M6.1 identifies only this reproduced standard plugin; arbitrary build
        # requirements are not guessed to be file finders.
        setuptools_surface_unresolved = True
        setuptools_surface_evidence.append(
            _evidence(
                root,
                pyproject_path,
                "Declared setuptools-scm build requirement may contribute package data "
                "through the active setuptools file-finder mechanism; M6.1 does not "
                "interpret plugin-provided file lists.",
                _line_number(pyproject_path, "setuptools-scm"),
            )
        )

    requirements = _requirements_files(root)
    for path in requirements:
        metadata_files.append(path.relative_to(root).as_posix())
        group = _requirements_group(path)
        parsed = _parse_requirements_file(root, path, group)
        dependencies.extend(parsed)
        legacy_groups.append(
            LegacyDependencyGroup(
                name=group,
                source_file=path.relative_to(root).as_posix(),
                distributions=sorted({item.distribution_name for item in parsed}),
                includes_groups=_requirements_includes(root, path),
                evidence=[_evidence(root, path, "Legacy requirements dependency group.")],
            )
        )

    group_sets = {item.name: set(item.distributions) for item in legacy_groups}
    for group in legacy_groups:
        inferred = [
            name
            for name, distributions in group_sets.items()
            if name != group.name and distributions and distributions < group_sets[group.name]
        ]
        group.aggregate_of = sorted(set([*group.includes_groups, *inferred]))

    pipfile_path = root / "Pipfile"
    if pipfile_path.is_file():
        try:
            with pipfile_path.open("rb") as handle:
                pipfile = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            pipfile = {}
        for section, group in (("packages", "runtime"), ("dev-packages", "dev")):
            values = pipfile.get(section) if isinstance(pipfile.get(section), dict) else {}
            for name, constraint_value in values.items():
                if not isinstance(name, str):
                    continue
                constraint = (
                    constraint_value
                    if isinstance(constraint_value, str)
                    else str(constraint_value.get("version", "unconstrained"))
                    if isinstance(constraint_value, dict)
                    else "unconstrained"
                )
                dependencies.append(
                    DependencyAssessment(
                        distribution_name=name,
                        declared_constraint=constraint if constraint != "*" else "unconstrained",
                        group=group,
                        launch_critical=group == "runtime",
                        evidence=[
                            _evidence(
                                root,
                                pipfile_path,
                                f"Declared in [{section}].",
                                _line_number(pipfile_path, name),
                            )
                        ],
                    )
                )
        pipfile_requires = (
            pipfile.get("requires") if isinstance(pipfile.get("requires"), dict) else {}
        )
        if (
            not project_python_static_authoritative
            and requires_python is None
            and isinstance(pipfile_requires.get("python_version"), str)
        ):
            requires_python = f"=={pipfile_requires['python_version']}.*"

    if not source_roots:
        source_roots = ["src"] if (root / "src").is_dir() else ["."]

    # Every source/search root that contributes to setuptools' authoritative
    # first-party surface must be representable inside the assessed repository.
    # Retaining only a safe subset while silently dropping another declared
    # root would make that subset look authoritative when it is not.
    root_metadata_path = next(
        (
            root / name
            for name in ("pyproject.toml", "setup.cfg", "setup.py")
            if (root / name).is_file()
        ),
        root / "pyproject.toml",
    )
    root_inspections: dict[str, PackagingRootInspection] = {}

    def inspect_declared_root(value: str) -> PackagingRootInspection:
        inspection = root_inspections.get(value)
        if inspection is None:
            inspection = inspect_setuptools_packaging_root(root, value)
            root_inspections[value] = inspection
            if inspection.status == "UNSAFE":
                setuptools_external_packaging_roots.append(value)
                setuptools_external_packaging_root_evidence.append(
                    _evidence(
                        root,
                        root_metadata_path,
                        "Authoritative setuptools packaging root escapes the assessed "
                        f"repository boundary: {value!r}.",
                        _line_number(root_metadata_path, value),
                    )
                )
        return inspection

    def safe_roots(values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            inspection = inspect_declared_root(value)
            if inspection.status == "UNSAFE" or inspection.normalized_root is None:
                continue
            if inspection.normalized_root not in result:
                result.append(inspection.normalized_root)
        return result

    source_roots = safe_roots(source_roots)
    package_discovery_rules = [
        (safe_roots(where), include, exclude, namespaces)
        for where, include, exclude, namespaces in package_discovery_rules
    ]
    package_directories = {
        package: inspection.normalized_root
        for package, directory in package_directories.items()
        for inspection in [inspect_declared_root(directory)]
        if inspection.status != "UNSAFE" and inspection.normalized_root is not None
    }
    # Setuptools' ordinary automatic discovery applies when its build backend
    # is selected but source metadata has not selected packages, find rules, or
    # standalone modules. This makes the resolved existing ``packages`` model
    # the single source surface for downstream planning and wheel validation.
    if (
        isinstance(build_backend, str)
        and build_backend.startswith("setuptools.")
        and not packages
        and not py_modules
        and not package_discovery_rules
        and not setuptools_package_selection_configured
        and not setuptools_surface_unresolved
        and not setuptools_external_packaging_roots
    ):
        if any(package_directories):
            named_packages = _discover_named_setuptools_packages(root, package_directories)
            if named_packages is None:
                setuptools_surface_unresolved = True
                setuptools_surface_evidence.append(
                    _evidence(
                        root, root_metadata_path,
                        "Automatic named package-dir discovery cannot establish every "
                        "declared mapped package root; generic layout fallback is unsafe.",
                    )
                )
            else:
                packages = named_packages
        else:
            automatic_root = (
                source_roots[0]
                if len(source_roots) == 1
                else "src"
                if (root / "src").is_dir()
                else "."
            )
            automatic_setuptools_src_layout = "" in package_directories or automatic_root == "src"
            automatic_setuptools_root = automatic_root
            package_discovery_rules.append(
                (
                    [automatic_root],
                    ["*"],
                    [] if automatic_setuptools_src_layout
                    else list(_SETUPTOOLS_79_FLAT_PACKAGE_DEFAULT_EXCLUDES),
                    True,
                )
            )
    if package_discovery_rules:
        discovered_packages = {
            package
            for where, include, exclude, namespaces in package_discovery_rules
            for package in _discover_setuptools_packages(
                root,
                where,
                package_directories,
                include,
                exclude,
                namespaces,
            )
        }
        if automatic_setuptools_root == "." and not automatic_setuptools_src_layout:
            top_level_packages = {package.split(".", 1)[0] for package in discovered_packages}
            if len(top_level_packages) > 1:
                # Setuptools rejects implicit flat layouts with multiple
                # top-level packages rather than building an arbitrary subset.
                # Leave the packaging surface unresolved so downstream source
                # constraints remain conservative until metadata is explicit.
                discovered_packages = set()
                automatic_setuptools_flat_surface_ambiguous = True
                setuptools_surface_unresolved = True
                setuptools_surface_evidence.append(
                    _evidence(
                        root,
                        root_metadata_path,
                        "Automatic flat-layout package discovery found multiple top-level "
                        "packages; setuptools would refuse the ambiguous build until package "
                        "selection is explicit.",
                        _line_number(root_metadata_path, "build-backend"),
                    )
                )
        packages = sorted({*packages, *discovered_packages})
    if automatic_setuptools_root is not None and (
        automatic_setuptools_src_layout or not packages
    ) and not automatic_setuptools_flat_surface_ambiguous:
        # Setuptools' default source-layout finder discovers top-level modules
        # as well as packages.  Its flat-layout finder selects a package
        # surface in preference to loose modules: setuptools 79.0.1 implements
        # ``_analyse_flat_packages() or _analyse_flat_modules()``. Therefore
        # only a package-free flat layout contributes automatic py_modules.
        # Explicit configuration never reaches this branch.
        discovered_modules = _discover_setuptools_py_modules(
            root,
            [automatic_setuptools_root],
            excluded_modules=(
                list(_SETUPTOOLS_79_FLAT_MODULE_DEFAULT_EXCLUDES)
                if not automatic_setuptools_src_layout
                else None
            ),
        )
        if not automatic_setuptools_src_layout and len(discovered_modules) > 1:
            # Mirroring the bounded flat package policy above prevents an
            # undeclared multi-module distribution from becoming a fabricated
            # wheel surface.
            discovered_modules = []
            setuptools_surface_unresolved = True
            setuptools_surface_evidence.append(
                _evidence(
                    root,
                    root_metadata_path,
                    "Automatic flat-layout module discovery found multiple top-level "
                    "modules; setuptools would refuse the ambiguous build until module "
                    "selection is explicit.",
                    _line_number(root_metadata_path, "build-backend"),
                )
            )
        py_modules = discovered_modules
    layout = (
        "src"
        if any(Path(value).as_posix().rstrip("/") == "src" for value in source_roots)
        else "flat"
    )

    lockfiles = [
        name
        for name in ("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock")
        if (root / name).is_file()
    ]
    for name in ("Pipfile", ".python-version"):
        if (root / name).is_file():
            metadata_files.append(name)

    python_version_file: str | None = None
    version_path = root / ".python-version"
    if version_path.is_file():
        python_version_file = version_path.read_text(encoding="utf-8-sig").strip() or None
        python_evidence.append(_evidence(root, version_path, "Explicit .python-version value.", 1))
    documented_versions, documented_evidence = _documented_python_versions(root)
    python_evidence.extend(documented_evidence)

    return MetadataResult(
        project=PackagingAssessment(
            metadata_files=sorted(set(metadata_files)),
            distribution_name=distribution_name,
            version=project_version,
            build_backend=build_backend,
            layout=layout,
            source_roots=source_roots,
            packages=packages,
            py_modules=py_modules,
            package_directories=package_directories,
            package_data=package_data,
            exclude_package_data=exclude_package_data,
            package_data_evidence=package_data_evidence,
            exclude_package_data_evidence=exclude_package_data_evidence,
            entry_points=entry_points,
            optional_dependency_groups=optional_groups,
            legacy_dependency_groups=legacy_groups,
            lockfiles=lockfiles,
        ),
        python=PythonRequirementAssessment(
            requires_python=requires_python,
            python_version_file=python_version_file,
            ruff_target_version=ruff_target,
            documented_versions=documented_versions,
            status=FindingStatus.DETECTED if requires_python else FindingStatus.NEEDS_VALIDATION,
            evidence=python_evidence,
        ),
        dependencies=_merge_dependencies(dependencies),
        uv_workspace=uv_workspace,
        uv_workspace_source=uv_workspace_source,
        uv_workspace_evidence=uv_workspace_evidence,
        setuptools_surface_unresolved=setuptools_surface_unresolved,
        setuptools_surface_evidence=setuptools_surface_evidence,
        setuptools_external_packaging_roots=sorted(set(setuptools_external_packaging_roots)),
        setuptools_external_packaging_root_evidence=setuptools_external_packaging_root_evidence,
        dynamic_dependency_evidence=dynamic_dependency_evidence,
        dynamic_entry_point_evidence=dynamic_entry_point_evidence,
    )
