"""Static runtime-resource and dotenv discovery."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

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


def _safe_package_data_pattern(pattern: str) -> bool:
    """Return whether a setuptools package-data pattern stays under its package root."""

    normalized = pattern.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(normalized) and not path.is_absolute() and not PureWindowsPath(
        pattern
    ).is_absolute() and ".." not in path.parts


def _known_packages(project: PackagingAssessment) -> set[str]:
    """Return only package identities established by static packaging metadata."""

    return {
        package
        for package in [
            *project.packages,
            *(name for name in project.package_directories if name),
            *(name for name in project.package_data if name != "*"),
        ]
        if package and package != "*"
    }


def _physical_package_roots(
    root: Path, project: PackagingAssessment, package: str
) -> list[Path]:
    """Resolve a declared installed package name to existing source directories."""

    candidates: list[Path] = []
    explicit = project.package_directories.get(package)
    if explicit is not None:
        candidates.append(root / explicit)
    else:
        base = project.package_directories.get("")
        if base is not None:
            candidates.append(root / base / Path(*package.split(".")))
        else:
            candidates.extend(
                root / source_root / Path(*package.split("."))
                for source_root in project.source_roots
            )
            candidates.append(root / Path(*package.split(".")))

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


def resolve_package_data_members(
    root: Path, project: PackagingAssessment | None
) -> list[ResolvedPackageDataMember]:
    """Resolve existing safe package-data source files and installed wheel member paths."""

    if project is None:
        return []
    resolved_root = root.resolve()
    resolved_members: list[ResolvedPackageDataMember] = []
    seen: set[tuple[str, str, str, str]] = set()
    for declared_package, patterns in project.package_data.items():
        packages = _known_packages(project) if declared_package == "*" else {declared_package}
        for package in packages:
            for package_root in _physical_package_roots(root, project, package):
                resolved_package_root = package_root.resolve()
                for pattern in patterns:
                    if not _safe_package_data_pattern(pattern):
                        continue
                    try:
                        matches = package_root.glob(pattern)
                    except (OSError, ValueError):
                        continue
                    for candidate in matches:
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                        try:
                            resolved = candidate.resolve()
                            resolved.relative_to(resolved_package_root)
                            source_path = resolved.relative_to(resolved_root).as_posix()
                            package_relative = resolved.relative_to(
                                resolved_package_root
                            ).as_posix()
                        except ValueError:
                            continue
                        installed_member_path = str(
                            PurePosixPath(*package.split(".")) / package_relative
                        )
                        evidence = Evidence(
                            file="pyproject.toml",
                            detail=(
                                "Authoritative setuptools package-data declaration "
                                f"{declared_package} = {pattern!r} includes this runtime resource."
                            ),
                        )
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


def _path_uses(node: ast.Call) -> list[tuple[ast.AST, str]]:
    name = _qualified_name(node.func)
    method = name.split(".")[-1].lower()
    if name == "open" and node.args:
        return [(node.args[0], _open_access(name, node))]
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
    if name in {"os.listdir", "os.scandir"} and node.args:
        return [(node.args[0], "read")]
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
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for expression, mode in _path_uses(node):
                values = _path_values(
                    expression,
                    root=root,
                    source_path=path,
                    assignments=assignments,
                    returns=returns,
                )
                for value in values:
                    if not _looks_like_resource_literal(value):
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
                                    f"Static {mode} path use through "
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
    literals, access_modes, unresolved = _literal_evidence(root, source_roots, application_files)
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
