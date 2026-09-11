"""Static runtime-resource and dotenv discovery."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from python_deployment_builder.analysis.ast_utils import call_argument
from python_deployment_builder.analysis.imports import EXCLUDED_DIRECTORIES
from python_deployment_builder.models import (
    ConfigurationRequirement,
    Evidence,
    FindingStatus,
    PackagingAssessment,
    ResourceRequirement,
)


@dataclass(frozen=True)
class ResolvedPackageDataMember:
    """A safe concrete setuptools package-data member and its wheel destination."""

    package_name: str
    pattern: str
    source_path: str
    installed_member_path: str
    evidence: Evidence


@dataclass(frozen=True)
class ResolvedPackagedPythonSource:
    """A concrete first-party Python source member expected in the wheel."""

    source_path: str
    installed_member_path: str
    package_name: str | None
    kind: str


def _safe_package_data_pattern(pattern: str) -> bool:
    """Return whether a setuptools package-data pattern stays under its package root."""

    normalized = pattern.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(normalized) and not path.is_absolute() and not PureWindowsPath(
        pattern
    ).is_absolute() and ".." not in path.parts


def _known_packages(project: PackagingAssessment) -> set[str]:
    """Return package identities selected by authoritative packaging metadata.

    ``package_data`` and ``exclude_package_data`` constrain files within a
    selected package; they never select a package themselves.  Physical
    package-dir mappings likewise locate selected packages, but do not create
    their identities.
    """

    return {package for package in project.packages if package and package != "*"}


def _physical_package_roots(
    root: Path, project: PackagingAssessment, package: str
) -> list[Path]:
    """Resolve a declared installed package name to existing source directories."""

    candidates: list[Path] = []
    explicit = project.package_directories.get(package)
    if explicit is not None:
        candidates.append(root / explicit)
    else:
        package_parts = package.split(".")
        parent_mappings = [
            mapping
            for mapping in project.package_directories
            if mapping and (package == mapping or package.startswith(f"{mapping}."))
        ]
        if parent_mappings:
            parent = max(parent_mappings, key=lambda mapping: len(mapping.split(".")))
            remainder = package_parts[len(parent.split(".")) :]
            candidates.append(root / project.package_directories[parent] / Path(*remainder))
        else:
            base = project.package_directories.get("")
            if base is not None:
                candidates.append(root / base / Path(*package_parts))
            else:
                candidates.extend(
                    root / source_root / Path(*package_parts)
                    for source_root in project.source_roots
                )
                candidates.append(root / Path(*package_parts))

    resolved_root = root.resolve()
    roots: list[Path] = []
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        try:
            candidate.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        if candidate not in roots:
            roots.append(candidate)
    return roots


def _matching_package_data_files(
    package_root: Path, pattern: str
) -> list[tuple[Path, str]]:
    """Resolve safe package-relative glob matches using one matcher for include/exclude rules."""

    if not _safe_package_data_pattern(pattern):
        return []
    try:
        matches = package_root.glob(pattern)
    except (OSError, ValueError):
        return []
    resolved_package_root = package_root.resolve()
    pattern_parts = PurePosixPath(pattern.replace("\\", "/")).parts
    explicitly_includes_dotfile = any(part.startswith(".") for part in pattern_parts)
    resolved_matches: list[tuple[Path, str]] = []
    for candidate in matches:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            resolved = candidate.resolve()
            package_relative = resolved.relative_to(resolved_package_root).as_posix()
        except ValueError:
            continue
        # Setuptools package-data globs do not implicitly select dotfiles. Keep
        # the existing pathlib matcher, but filter its broader hidden-file behavior.
        if not explicitly_includes_dotfile and any(
            part.startswith(".") for part in PurePosixPath(package_relative).parts
        ):
            continue
        resolved_matches.append((resolved, package_relative))
    return resolved_matches


def _package_data_evidence(
    project: PackagingAssessment, declared_package: str, pattern: str
) -> Evidence:
    """Return the parsed declaration evidence without assuming a metadata format."""

    return project.package_data_evidence.get(declared_package, {}).get(
        pattern,
        Evidence(
            file=(project.metadata_files[0] if project.metadata_files else "packaging metadata"),
            detail=(
                "Authoritative setuptools package-data declaration "
                f"{declared_package} = {pattern!r} includes this runtime resource."
            ),
        ),
    )


def resolve_package_data_members(
    root: Path, project: PackagingAssessment | None
) -> list[ResolvedPackageDataMember]:
    """Resolve existing safe package-data source files and installed wheel member paths."""

    if project is None:
        return []
    resolved_root = root.resolve()
    resolved_members: list[ResolvedPackageDataMember] = []
    seen: set[tuple[str, str, str, str]] = set()
    selected_packages = _known_packages(project)
    for declared_package, patterns in project.package_data.items():
        packages = (
            selected_packages
            if declared_package == "*"
            else {declared_package} & selected_packages
        )
        for package in packages:
            for package_root in _physical_package_roots(root, project, package):
                exclusion_patterns = [
                    *project.exclude_package_data.get(package, []),
                    *project.exclude_package_data.get("*", []),
                ]
                excluded = {
                    resolved
                    for exclusion in exclusion_patterns
                    for resolved, _relative in _matching_package_data_files(package_root, exclusion)
                }
                for pattern in patterns:
                    for resolved, package_relative in _matching_package_data_files(
                        package_root, pattern
                    ):
                        if resolved in excluded:
                            continue
                        try:
                            source_path = resolved.relative_to(resolved_root).as_posix()
                        except ValueError:
                            continue
                        installed_member_path = str(
                            PurePosixPath(*package.split(".")) / package_relative
                        )
                        evidence = _package_data_evidence(project, declared_package, pattern)
                        identity = (
                            package,
                            pattern,
                            source_path,
                            installed_member_path,
                        )
                        if identity not in seen:
                            seen.add(identity)
                            resolved_members.append(
                                ResolvedPackageDataMember(
                                    package_name=package,
                                    pattern=pattern,
                                    source_path=source_path,
                                    installed_member_path=installed_member_path,
                                    evidence=evidence,
                                )
                            )
    return sorted(
        resolved_members,
        key=lambda item: (
            item.source_path,
            item.installed_member_path,
            item.package_name,
            item.pattern,
        ),
    )


def _safe_python_source(path: Path, root: Path) -> Path | None:
    """Return a regular in-repository Python file without following symlinks."""

    if path.is_symlink() or not path.is_file() or path.suffix != ".py":
        return None
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def _physical_py_module_candidates(
    root: Path, project: PackagingAssessment, module: str
) -> list[Path]:
    relative = Path(*module.split(".")).with_suffix(".py")
    candidates: list[Path] = []
    base = project.package_directories.get("")
    if base is not None:
        candidates.append(root / base / relative)
    candidates.extend(root / source_root / relative for source_root in project.source_roots)
    candidates.append(root / relative)
    resolved: list[Path] = []
    for candidate in candidates:
        safe = _safe_python_source(candidate, root)
        if safe is not None and safe not in resolved:
            resolved.append(safe)
    return resolved


def resolve_packaged_python_sources(
    root: Path, project: PackagingAssessment | None
) -> list[ResolvedPackagedPythonSource]:
    """Resolve the supported setuptools Python surface without importing it.

    Packages contribute only modules directly in each authoritative package root;
    subpackages must be explicitly listed or discovered themselves.  Standalone
    modules are admitted only through authoritative ``py_modules`` metadata.
    """

    if project is None:
        return []
    resolved_root = root.resolve()
    resolved: list[ResolvedPackagedPythonSource] = []
    seen: set[tuple[str, str]] = set()
    for package in sorted(set(project.packages)):
        for package_root in _physical_package_roots(root, project, package):
            for candidate in sorted(package_root.glob("*.py")):
                safe = _safe_python_source(candidate, root)
                if safe is None:
                    continue
                source_path = safe.relative_to(resolved_root).as_posix()
                installed = str(
                    PurePosixPath(*package.split(".")) / safe.name
                )
                identity = (source_path, installed)
                if identity not in seen:
                    seen.add(identity)
                    resolved.append(
                        ResolvedPackagedPythonSource(
                            source_path=source_path,
                            installed_member_path=installed,
                            package_name=package,
                            kind="package_module",
                        )
                    )
    for module in sorted(set(project.py_modules)):
        if not module or not all(part.isidentifier() for part in module.split(".")):
            continue
        for source in _physical_py_module_candidates(root, project, module):
            source_path = source.relative_to(resolved_root).as_posix()
            installed = PurePosixPath(*module.split(".")).with_suffix(".py").as_posix()
            identity = (source_path, installed)
            if identity not in seen:
                seen.add(identity)
                resolved.append(
                    ResolvedPackagedPythonSource(
                        source_path=source_path,
                        installed_member_path=installed,
                        package_name=None,
                        kind="py_module",
                    )
                )
    return sorted(resolved, key=lambda item: (item.source_path, item.installed_member_path))


def package_surface_resolved(
    project: PackagingAssessment | None, repository_root: Path | None = None
) -> bool:
    """Whether M6.1 has an authoritative Python wheel-surface model.

    A build backend establishes only that a project might be buildable.  The
    package/source resolver is deliberately a bounded static setuptools model;
    it must not silently stand in for Hatchling, Poetry, or arbitrary PEP 517
    backend discovery.
    """

    resolved_backend = bool(
        project
        and project.build_backend
        and project.build_backend.partition(":")[0] == "setuptools.build_meta"
    )
    if not resolved_backend or repository_root is None:
        return resolved_backend
    # setup.py fields are not persisted in PackagingAssessment. Re-inspect
    # locally when planning or validating a wheel so a dynamic selector cannot
    # bypass the source-surface authority contract through a stale/manual plan.
    from python_deployment_builder.analysis.metadata import (
        setuptools_packaging_surface_resolved,
    )

    return setuptools_packaging_surface_resolved(repository_root)


def _declared_package_data(
    root: Path, project: PackagingAssessment | None
) -> dict[str, list[Evidence]]:
    """Group concrete setuptools package-data evidence by physical source path."""

    declared: dict[str, list[Evidence]] = defaultdict(list)
    for member in resolve_package_data_members(root, project):
        if member.evidence not in declared[member.source_path]:
            declared[member.source_path].append(member.evidence)
    return declared

RESOURCE_DIRECTORIES = {
    "assets": "assets",
    "config": "configuration",
    "icons": "icons",
    "profiles": "profiles",
    "prompts": "prompts",
    "schemas": "schemas",
    "templates": "templates",
}
RESOURCE_FILES = {"README.md": "documentation", ".env.example": "configuration_example"}
RESOURCE_SUFFIXES = {
    ".cfg",
    ".csv",
    ".gif",
    ".html",
    ".ico",
    ".ini",
    ".jpeg",
    ".jpg",
    ".json",
    ".md",
    ".pdf",
    ".png",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def _kind(path: Path) -> str:
    if path.is_dir():
        return RESOURCE_DIRECTORIES.get(path.name.lower(), "resource_directory")
    suffixes = {
        ".html": "html",
        ".json": "configuration",
        ".ico": "icon",
        ".gif": "image",
        ".jpeg": "image",
        ".jpg": "image",
        ".png": "image",
        ".svg": "image",
        ".pdf": "document",
    }
    return suffixes.get(path.suffix.lower(), "resource_file")


def _looks_like_resource_literal(value: str) -> bool:
    normalized = value.replace("\\", "/").strip()
    if not normalized or "\n" in normalized or normalized.startswith(("http://", "https://")):
        return False
    path = Path(normalized)
    return path.suffix.lower() in RESOURCE_SUFFIXES or any(
        part.lower() in RESOURCE_DIRECTORIES for part in path.parts
    )


def _resolve_literal(root: Path, source_path: Path, value: str) -> list[Path]:
    normalized = value.replace("\\", "/").strip().lstrip("./")
    if not normalized or Path(normalized).is_absolute():
        return []
    relative = Path(normalized)
    candidates = [root / relative, source_path.parent / relative]
    if len(relative.parts) == 1:
        for parent in (source_path.parent, *source_path.parents):
            if parent == root.parent:
                break
            candidates.append(parent / relative)
    found: list[Path] = []
    for candidate in candidates:
        try:
            candidate.resolve().relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.exists() and candidate not in found:
            found.append(candidate)
    return found


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _binding_name(node: ast.AST) -> str | None:
    name = _qualified_name(node)
    return name or None


def _bindings(tree: ast.AST) -> tuple[dict[str, ast.AST], dict[str, ast.AST]]:
    assignments: dict[str, ast.AST] = {}
    returns: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if name := _binding_name(target):
                    assignments[name] = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if name := _binding_name(node.target):
                assignments[name] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            returned = next(
                (
                    child.value
                    for child in ast.walk(node)
                    if isinstance(child, ast.Return) and child.value is not None
                ),
                None,
            )
            if returned is not None:
                returns[node.name] = returned

    def static_sequence(node: ast.AST) -> list[ast.AST]:
        if isinstance(node, ast.Name) and node.id in assignments:
            return static_sequence(assignments[node.id])
        if isinstance(node, (ast.List, ast.Tuple)):
            return list(node.elts)
        if (
            isinstance(node, ast.Call)
            and _qualified_name(node.func) == "enumerate"
            and node.args
        ):
            return [
                ast.Tuple(elts=[ast.Constant(index), value], ctx=ast.Load())
                for index, value in enumerate(static_sequence(node.args[0]))
            ]
        return []

    def bind_pattern(target: ast.AST, values: list[ast.AST]) -> None:
        if isinstance(target, ast.Name) and values:
            assignments[target.id] = ast.Tuple(elts=values, ctx=ast.Load())
            return
        if not isinstance(target, (ast.List, ast.Tuple)):
            return
        for index, child_target in enumerate(target.elts):
            child_values = [
                value.elts[index]
                for value in values
                if isinstance(value, (ast.List, ast.Tuple)) and len(value.elts) > index
            ]
            bind_pattern(child_target, child_values)

    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            bind_pattern(node.target, static_sequence(node.iter))
    return assignments, returns


_LEGACY_IMPORTLIB_RESOURCE_READS = frozenset(
    {"read_text", "read_binary", "open_text", "open_binary"}
)


def _resource_import_bindings(
    tree: ast.AST,
) -> tuple[set[str], set[str], dict[str, str], set[str], set[str]]:
    """Return proven importlib.resources and pkgutil resource bindings."""

    modules: set[str] = set()
    files: set[str] = set()
    reads: dict[str, str] = {}
    pkgutil_modules: set[str] = set()
    pkgutil_get_data: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib.resources":
                    modules.add(alias.asname or alias.name)
                elif alias.name == "pkgutil":
                    pkgutil_modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "resources":
                        modules.add(alias.asname or alias.name)
            elif node.module == "importlib.resources":
                for alias in node.names:
                    if alias.name == "files":
                        files.add(alias.asname or alias.name)
                    elif alias.name in _LEGACY_IMPORTLIB_RESOURCE_READS:
                        reads[alias.asname or alias.name] = alias.name
            elif node.module == "pkgutil":
                for alias in node.names:
                    if alias.name == "get_data":
                        pkgutil_get_data.add(alias.asname or alias.name)
    return modules, files, reads, pkgutil_modules, pkgutil_get_data


def _resource_package_roots(
    root: Path,
    package: str,
    source_roots: list[str],
    project: PackagingAssessment | None,
    *,
    require_initializer: bool = False,
) -> list[Path]:
    """Resolve a literal package anchor only through safe in-repository roots."""

    if not package or not all(part.isidentifier() for part in package.split(".")):
        return []
    candidates = _physical_package_roots(root, project, package) if project else []
    relative = Path(*package.split("."))
    candidates.extend(root / source_root / relative for source_root in source_roots)
    candidates.append(root / relative)
    resolved_root = root.resolve()
    safe: list[Path] = []
    for candidate in candidates:
        if (
            candidate.is_symlink()
            or not candidate.is_dir()
            or (require_initializer and not (candidate / "__init__.py").is_file())
        ):
            continue
        try:
            candidate.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        if candidate not in safe:
            safe.append(candidate)
    return safe


def _is_resource_files_call(
    node: ast.AST, module_bindings: set[str], files_bindings: set[str]
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _qualified_name(node.func)
    return name in files_bindings or any(name == f"{binding}.files" for binding in module_bindings)


def _legacy_resource_function_name(
    node: ast.AST,
    module_bindings: set[str],
    read_bindings: dict[str, str],
) -> str | None:
    """Return a proven legacy importlib.resources functional read name."""

    if not isinstance(node, ast.Call):
        return None
    name = _qualified_name(node.func)
    if name in read_bindings:
        return read_bindings[name]
    for binding in module_bindings:
        for function in _LEGACY_IMPORTLIB_RESOURCE_READS:
            if name == f"{binding}.{function}":
                return function
    return None


def _safe_resource_member(values: list[str]) -> bool:
    return all(
        value
        and not PurePosixPath(value.replace("\\", "/")).is_absolute()
        and not PureWindowsPath(value).is_absolute()
        and ".." not in PurePosixPath(value.replace("\\", "/")).parts
        for value in values
    )


def _implicit_resource_root(root: Path, source_path: Path) -> list[str]:
    """Return the safe caller-adjacent container for ``files()``.

    Python 3.12 resolves an omitted ``importlib.resources.files`` anchor from
    the caller module.  Resource analysis already visits only application
    source files, but still validates that the particular caller is a regular
    in-repository Python file before using its physical parent as an anchor.
    """

    source = _safe_python_source(source_path, root)
    if source is None:
        return []
    try:
        return [source.parent.relative_to(root.resolve()).as_posix()]
    except ValueError:
        return []


def _resource_package_anchor_values(
    node: ast.AST,
    *,
    root: Path,
    source_path: Path,
    source_roots: list[str],
    project: PackagingAssessment | None,
    assignments: dict[str, ast.AST],
    returns: dict[str, ast.AST],
    require_initializer: bool = False,
) -> list[str]:
    package_values = _path_values(
        node,
        root=root,
        source_path=source_path,
        assignments=assignments,
        returns=returns,
    )
    if len(package_values) != 1:
        return []
    return [
        package_root.relative_to(root.resolve()).as_posix()
        for package_root in _resource_package_roots(
            root,
            package_values[0],
            source_roots,
            project,
            require_initializer=require_initializer,
        )
    ]


def _pkgutil_resource_path_values(
    node: ast.Call,
    *,
    root: Path,
    source_path: Path,
    source_roots: list[str],
    project: PackagingAssessment | None,
    assignments: dict[str, ast.AST],
    returns: dict[str, ast.AST],
    module_bindings: set[str],
    get_data_bindings: set[str],
) -> list[str] | None:
    """Resolve a proven filesystem-package ``pkgutil.get_data`` read."""

    name = _qualified_name(node.func)
    if name not in get_data_bindings and not any(
        name == f"{binding}.get_data" for binding in module_bindings
    ):
        return None
    if len(node.args) > 2 or any(
        keyword.arg not in {"package", "resource"} for keyword in node.keywords
    ):
        return []
    package = call_argument(node, position=0, keyword="package")
    resource = call_argument(node, position=1, keyword="resource")
    if package is None or resource is None:
        return []
    package_roots = _resource_package_anchor_values(
        package,
        root=root,
        source_path=source_path,
        source_roots=source_roots,
        project=project,
        assignments=assignments,
        returns=returns,
        require_initializer=True,
    )
    members = _path_values(
        resource,
        root=root,
        source_path=source_path,
        assignments=assignments,
        returns=returns,
    )
    if (
        not package_roots
        or len(members) != 1
        or "\\" in members[0]
        or not _safe_resource_member(members)
    ):
        return []
    return _combine_paths(package_roots, members)


def _legacy_importlib_resource_path_values(
    node: ast.Call,
    *,
    root: Path,
    source_path: Path,
    source_roots: list[str],
    project: PackagingAssessment | None,
    assignments: dict[str, ast.AST],
    returns: dict[str, ast.AST],
    module_bindings: set[str],
    read_bindings: dict[str, str],
) -> tuple[str, list[str]] | None:
    """Resolve the bounded two-argument legacy resource read API statically."""

    function = _legacy_resource_function_name(node, module_bindings, read_bindings)
    if function is None:
        return None
    # Python 3.12 legacy resource calls address one direct member of a
    # package.  Keep dynamic, nested, and traversal-like members unresolved.
    if len(node.args) != 2:
        return function, []
    allowed_keywords = {"encoding", "errors"} if function.endswith("text") else set()
    if any(keyword.arg not in allowed_keywords for keyword in node.keywords):
        return function, []
    package_roots = _resource_package_anchor_values(
        node.args[0],
        root=root,
        source_path=source_path,
        source_roots=source_roots,
        project=project,
        assignments=assignments,
        returns=returns,
    )
    members = _path_values(
        node.args[1],
        root=root,
        source_path=source_path,
        assignments=assignments,
        returns=returns,
    )
    if (
        not package_roots
        or len(members) != 1
        or not _safe_resource_member(members)
        or len(PurePosixPath(members[0].replace("\\", "/")).parts) != 1
    ):
        return function, []
    return function, _combine_paths(package_roots, members)


def _importlib_resource_path_values(
    node: ast.AST,
    *,
    root: Path,
    source_path: Path,
    source_roots: list[str],
    project: PackagingAssessment | None,
    assignments: dict[str, ast.AST],
    returns: dict[str, ast.AST],
    module_bindings: set[str],
    files_bindings: set[str],
) -> list[str] | None:
    """Resolve a bounded ``importlib.resources.files`` path expression statically."""

    if _is_resource_files_call(node, module_bindings, files_bindings):
        if not isinstance(node, ast.Call):
            return []
        if not node.args:
            # ``anchor=`` is the Python 3.12 spelling.  Deliberately leave
            # deprecated ``package=`` unresolved rather than treating either
            # keyword form as the zero-argument implicit caller anchor.
            if not node.keywords:
                return _implicit_resource_root(root, source_path)
            if len(node.keywords) == 1 and node.keywords[0].arg == "anchor":
                return _resource_package_anchor_values(
                    node.keywords[0].value,
                    root=root,
                    source_path=source_path,
                    source_roots=source_roots,
                    project=project,
                    assignments=assignments,
                    returns=returns,
                )
            return []
        if len(node.args) != 1 or node.keywords:
            return []
        return _resource_package_anchor_values(
            node.args[0],
            root=root,
            source_path=source_path,
            source_roots=source_roots,
            project=project,
            assignments=assignments,
            returns=returns,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "joinpath"
    ):
        base = _importlib_resource_path_values(
            node.func.value,
            root=root,
            source_path=source_path,
            source_roots=source_roots,
            project=project,
            assignments=assignments,
            returns=returns,
            module_bindings=module_bindings,
            files_bindings=files_bindings,
        )
        if base is None:
            return None
        parts = [
            _path_values(
                argument,
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
            )
            for argument in node.args
        ]
        if not base or any(not part or not _safe_resource_member(part) for part in parts):
            return []
        for part in parts:
            base = _combine_paths(base, part)
        return base
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _importlib_resource_path_values(
            node.left,
            root=root,
            source_path=source_path,
            source_roots=source_roots,
            project=project,
            assignments=assignments,
            returns=returns,
            module_bindings=module_bindings,
            files_bindings=files_bindings,
        )
        if base is None:
            return None
        parts = _path_values(
            node.right,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
        )
        if not base or not parts or not _safe_resource_member(parts):
            return []
        return _combine_paths(base, parts)
    return None


def _combine_paths(left: list[str], right: list[str]) -> list[str]:
    return [(Path(first) / second).as_posix() for first in left for second in right]


def _path_values(
    node: ast.AST,
    *,
    root: Path,
    source_path: Path,
    assignments: dict[str, ast.AST],
    returns: dict[str, ast.AST],
    seen: frozenset[str] = frozenset(),
) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [
            value
            for element in node.elts
            for value in _path_values(
                element,
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
                seen=seen,
            )
        ]
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return [source_path.relative_to(root).as_posix()]
        if node.id in assignments and node.id not in seen:
            return _path_values(
                assignments[node.id],
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
                seen=seen | {node.id},
            )
        return []
    if isinstance(node, ast.Attribute):
        name = _qualified_name(node)
        if name in assignments and name not in seen:
            return _path_values(
                assignments[name],
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
                seen=seen | {name},
            )
        if node.attr == "parent":
            return [
                Path(value).parent.as_posix()
                for value in _path_values(
                    node.value,
                    root=root,
                    source_path=source_path,
                    assignments=assignments,
                    returns=returns,
                    seen=seen,
                )
            ]
        return []
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "parents"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
        and node.slice.value >= 0
    ):
        values = _path_values(
            node.value.value,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
        return [
            Path(value).parents[node.slice.value].as_posix()
            for value in values
            if len(Path(value).parents) > node.slice.value
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
        left = _path_values(
            node.left,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
        right = _path_values(
            node.right,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
        return _combine_paths(left, right) if left and right else []
    if not isinstance(node, ast.Call):
        return []
    name = _qualified_name(node.func)
    method = name.split(".")[-1].lower()
    if name in {"Path", "pathlib.Path"} and node.args:
        return _path_values(
            node.args[0],
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
    if name in {"os.path.dirname", "posixpath.dirname", "ntpath.dirname"} and node.args:
        values = _path_values(
            node.args[0],
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
        return [Path(value).parent.as_posix() for value in values]
    if name in {"os.path.abspath", "os.path.realpath"} and node.args:
        return _path_values(
            node.args[0],
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
    if name in {"os.path.join", "posixpath.join", "ntpath.join"} and node.args:
        values = [""]
        for argument in node.args:
            part = _path_values(
                argument,
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
                seen=seen,
            )
            if not part:
                return []
            values = _combine_paths(values, part)
        return [value.lstrip("/") for value in values]
    if isinstance(node.func, ast.Attribute) and method in {"joinpath", "with_name"}:
        base = _path_values(
            node.func.value,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
        parts = [
            _path_values(
                argument,
                root=root,
                source_path=source_path,
                assignments=assignments,
                returns=returns,
                seen=seen,
            )
            for argument in node.args
        ]
        if not base or any(not part for part in parts):
            return []
        if method == "with_name":
            base = [Path(value).parent.as_posix() for value in base]
        for part in parts:
            base = _combine_paths(base, part)
        return base
    if isinstance(node.func, ast.Attribute) and method in {"as_uri", "resolve", "absolute"}:
        return _path_values(
            node.func.value,
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen,
        )
    if method in returns and method not in seen:
        return _path_values(
            returns[method],
            root=root,
            source_path=source_path,
            assignments=assignments,
            returns=returns,
            seen=seen | {method},
        )
    return []


def _open_access(name: str, node: ast.Call) -> str:
    mode_node: ast.AST | None = None
    if name == "open" and len(node.args) >= 2:
        mode_node = node.args[1]
    elif name != "open" and node.args:
        mode_node = node.args[0]
    mode_node = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "mode"),
        mode_node,
    )
    mode = mode_node.value if isinstance(mode_node, ast.Constant) else "r"
    if not isinstance(mode, str):
        return "unknown"
    writes = any(flag in mode for flag in "wax+")
    reads = "r" in mode or "+" in mode
    if writes and reads:
        return "read_write"
    return "write" if writes else "read"


def _directory_read_bindings(tree: ast.AST) -> set[str]:
    """Collect explicit os.listdir/scandir spellings for the existing reader."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    names.update(
                        f"{alias.asname or 'os'}.{method}" for method in ("listdir", "scandir")
                    )
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "os":
            names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in {"listdir", "scandir"}
            )
    return names


def _path_uses(
    node: ast.Call, directory_reads: set[str] | None = None
) -> list[tuple[ast.AST, str]]:
    name = _qualified_name(node.func)
    method = name.split(".")[-1].lower()
    if name == "open":
        path = call_argument(node, position=0, keyword="file")
        return [(path, _open_access(name, node))] if path is not None else []
    if method == "open" and isinstance(node.func, ast.Attribute):
        library_open = _qualified_name(node.func.value).split(".")[0].lower() in {
            "fitz",
            "image",
            "pymupdf",
        }
        if library_open and node.args:
            return [(node.args[0], "read")]
        return [(node.func.value, _open_access(name, node))]
    if method in {"read_bytes", "read_text"} and isinstance(node.func, ast.Attribute):
        return [(node.func.value, "read")]
    if method in {"touch", "write_bytes", "write_text"} and isinstance(node.func, ast.Attribute):
        return [(node.func.value, "write")]
    if method == "iconbitmap":
        values = [node.args[0]] if node.args else []
        values.extend(keyword.value for keyword in node.keywords if keyword.arg == "default")
        return [(value, "read") for value in values]
    if method == "photoimage":
        return [
            (keyword.value, "read") for keyword in node.keywords if keyword.arg == "file"
        ]
    if method == "create_window":
        values = [node.args[1]] if len(node.args) >= 2 else []
        values.extend(keyword.value for keyword in node.keywords if keyword.arg in {"url", "html"})
        return [(value, "read") for value in values]
    if method in {"load_html", "load_url"} and node.args:
        return [(node.args[0], "read")]
    if method == "process":
        return [
            (keyword.value, "read") for keyword in node.keywords if keyword.arg == "args"
        ]
    if method in {"iterdir", "glob", "rglob"} and isinstance(node.func, ast.Attribute):
        return [(node.func.value, "read")]
    if name in {"os.listdir", "os.scandir"} | (directory_reads or set()):
        path = call_argument(node, position=0, keyword="path")
        return [(path, "read")] if path is not None else []
    return []


def _merge_access(modes: set[str]) -> str:
    if "read_write" in modes or ({"read", "write"} <= modes):
        return "read_write"
    if "write" in modes:
        return "write"
    if "read" in modes:
        return "read"
    return "unknown"


def _literal_evidence(
    root: Path,
    source_roots: list[str],
    application_files: list[Path] | None,
    project: PackagingAssessment | None,
) -> tuple[dict[str, list[Evidence]], dict[str, set[str]], set[str]]:
    found: dict[str, list[Evidence]] = defaultdict(list)
    access: dict[str, set[str]] = defaultdict(set)
    unresolved: set[str] = set()
    files: set[Path] = set(application_files or [])
    if application_files is None:
        for source_root in source_roots:
            base = (root / source_root).resolve()
            if not base.is_dir():
                continue
            files.update(
                path
                for path in base.rglob("*.py")
                if not any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(root).parts)
            )
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            continue
        lines = source.splitlines()
        assignments, returns = _bindings(tree)
        directory_reads = _directory_read_bindings(tree)
        (
            module_bindings,
            files_bindings,
            read_bindings,
            pkgutil_modules,
            pkgutil_get_data,
        ) = _resource_import_bindings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            pkgutil_resource = _pkgutil_resource_path_values(
                node,
                root=root,
                source_path=path,
                source_roots=source_roots,
                project=project,
                assignments=assignments,
                returns=returns,
                module_bindings=pkgutil_modules,
                get_data_bindings=pkgutil_get_data,
            )
            legacy_resource = _legacy_importlib_resource_path_values(
                node,
                root=root,
                source_path=path,
                source_roots=source_roots,
                project=project,
                assignments=assignments,
                returns=returns,
                module_bindings=module_bindings,
                read_bindings=read_bindings,
            )
            uses: list[tuple[ast.AST, str, list[str] | None, str]] = []
            if pkgutil_resource is not None:
                uses.append((node, "read", pkgutil_resource, "pkgutil.get_data()"))
            elif legacy_resource is not None:
                function, values = legacy_resource
                # Detect these before generic ``receiver.read_text()`` handling;
                # their receiver is an importlib module, not a filesystem path.
                uses.append(
                    (
                        node,
                        "read",
                        values,
                        f"importlib.resources.{function}()",
                    )
                )
            else:
                for expression, mode in _path_uses(node, directory_reads):
                    resource_values = _importlib_resource_path_values(
                        expression,
                        root=root,
                        source_path=path,
                        source_roots=source_roots,
                        project=project,
                        assignments=assignments,
                        returns=returns,
                        module_bindings=module_bindings,
                        files_bindings=files_bindings,
                    )
                    uses.append(
                        (expression, mode, resource_values, "importlib.resources.files()")
                    )
            for expression, mode, resource_values, resource_api in uses:
                values = (
                    resource_values
                    if resource_values is not None
                    else _path_values(
                        expression,
                        root=root,
                        source_path=path,
                        assignments=assignments,
                        returns=returns,
                    )
                )
                for value in values:
                    if resource_values is None and not _looks_like_resource_literal(value):
                        continue
                    resolved_any = False
                    for resolved in _resolve_literal(root, path, value):
                        resolved_any = True
                        resource_path = resolved.relative_to(root).as_posix()
                        access[resource_path].add(mode)
                        found[resource_path].append(
                            Evidence(
                                file=relative,
                                line=node.lineno,
                                detail=(
                                    f"Static {mode} resource use through "
                                    f"{resource_api} resolves here."
                                    if resource_values is not None
                                    else f"Static {mode} path use through "
                                    f"{_qualified_name(node.func)} resolves here."
                                ),
                                excerpt=lines[node.lineno - 1].strip(),
                            )
                        )
                    if not resolved_any:
                        unresolved.add(value.replace("\\", "/"))
                        access[value.replace("\\", "/")].add(mode)
                        found[value.replace("\\", "/")].append(
                            Evidence(
                                file=relative,
                                line=node.lineno,
                                detail=(
                                    "Static path use did not resolve to an existing repository "
                                    "path."
                                ),
                                excerpt=lines[node.lineno - 1].strip(),
                            )
                        )
                if not values and any(
                    isinstance(child, ast.Constant)
                    and isinstance(child.value, str)
                    and _looks_like_resource_literal(child.value)
                    for child in ast.walk(expression)
                ):
                    rendered = ast.unparse(expression)
                    unresolved.add(rendered)
                    access[rendered].add(mode)
                    found[rendered].append(
                        Evidence(
                            file=relative,
                            line=node.lineno,
                            detail="Dynamic resource path could not be resolved statically.",
                            excerpt=lines[node.lineno - 1].strip(),
                        )
                    )
    return found, access, unresolved


def inspect_resources(
    root: Path,
    source_roots: list[str],
    *,
    application_files: list[Path] | None = None,
    project: PackagingAssessment | None = None,
) -> tuple[list[ResourceRequirement], list[ConfigurationRequirement]]:
    literals, access_modes, unresolved = _literal_evidence(
        root, source_roots, application_files, project
    )
    declared_package_data = _declared_package_data(root, project)
    resources: list[ResourceRequirement] = []
    for relative, references in sorted(literals.items()):
        path = root / relative
        exists = relative not in unresolved and path.exists()
        resources.append(
            ResourceRequirement(
                path=relative,
                kind=_kind(path) if exists else "unresolved_path_reference",
                access_mode=_merge_access(access_modes[relative]),
                packaging_status=(
                    "packaged"
                    if exists
                    and relative in declared_package_data
                    else "repository_adjacent"
                    if exists
                    else "unknown"
                ),
                status=FindingStatus.DETECTED if exists else FindingStatus.NEEDS_VALIDATION,
                evidence=(
                    [
                        Evidence(file=relative, detail="Referenced runtime resource exists."),
                        *declared_package_data.get(relative, []),
                        *references,
                    ]
                    if exists
                    else references
                ),
            )
        )

    known_resources = {resource.path for resource in resources}
    for relative, evidence in sorted(declared_package_data.items()):
        if relative in known_resources:
            continue
        path = root / relative
        resources.append(
            ResourceRequirement(
                path=relative,
                kind=_kind(path),
                access_mode="read",
                packaging_status="packaged",
                status=FindingStatus.DETECTED,
                evidence=[
                    Evidence(
                        file=relative,
                        detail="Declared package-data runtime resource exists.",
                    ),
                    *evidence,
                ],
            )
        )

    for name, kind in {**RESOURCE_DIRECTORIES, **RESOURCE_FILES}.items():
        path = root / name
        if not path.exists() or name in literals:
            continue
        resources.append(
            ResourceRequirement(
                path=name,
                kind=kind,
                access_mode="read",
                packaging_status="repository_adjacent",
                status=FindingStatus.INFERRED,
                evidence=[Evidence(file=name, detail="Conventional repository resource exists.")],
            )
        )

    configuration: list[ConfigurationRequirement] = []
    dotenv_example = root / ".env.example"
    if dotenv_example.is_file():
        configuration.append(
            ConfigurationRequirement(
                name=".env.example",
                kind="dotenv",
                secret=False,
                required_at_launch=None,
                description=(
                    "Example dotenv file documents configuration; real .env contents must never "
                    "be copied."
                ),
                status=FindingStatus.DETECTED,
                evidence=[
                    Evidence(file=".env.example", detail="Example configuration file exists.")
                ],
            )
        )
    if (root / ".env").is_file():
        configuration.append(
            ConfigurationRequirement(
                name=".env",
                kind="dotenv",
                secret=True,
                required_at_launch=None,
                description=(
                    "Developer dotenv file exists and must be excluded from generated deployment "
                    "metadata and copies."
                ),
                status=FindingStatus.DETECTED,
                evidence=[
                    Evidence(
                        file=".env",
                        detail="Potential secret-bearing file exists; contents not read.",
                    )
                ],
            )
        )
    resources.sort(key=lambda item: item.path.lower())
    return resources, configuration
