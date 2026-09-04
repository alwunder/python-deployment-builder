"""Static packaging and Python-version metadata inspection."""

from __future__ import annotations

import ast
import configparser
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

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


def _literal_setup_arguments(path: Path) -> dict[str, Any]:
    """Read literal setup(...) keyword values without executing setup.py."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name != "setup":
            continue
        values: dict[str, Any] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            try:
                values[keyword.arg] = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                continue
        return values
    return {}


def _literal_module_attribute(root: Path, attribute: str) -> str | None:
    """Resolve a setuptools dynamic version attr only when it is a string literal."""

    try:
        module_name, attribute_name = attribute.rsplit(".", 1)
    except ValueError:
        return None
    if not all(part.isidentifier() for part in module_name.split(".")):
        return None
    relative = Path(*module_name.split("."))
    candidates = [
        root / relative.with_suffix(".py"),
        root / relative / "__init__.py",
        root / "src" / relative.with_suffix(".py"),
        root / "src" / relative / "__init__.py",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            return None
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
                    return None
                if not isinstance(value, str) or not value.strip():
                    return None
                resolved_values.append(value)
        if len(resolved_values) == 1:
            return resolved_values[0]
        if resolved_values:
            return None
    return None


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
    package_directories: dict[str, str] = {}
    package_data: dict[str, list[str]] = {}
    layout = "unknown"
    python_evidence: list[Evidence] = []

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        metadata_files.append("pyproject.toml")
        with pyproject_path.open("rb") as handle:
            document: dict[str, Any] = tomllib.load(handle)
        project = document.get("project") if isinstance(document.get("project"), dict) else {}
        build_system = (
            document.get("build-system") if isinstance(document.get("build-system"), dict) else {}
        )
        distribution_name = project.get("name") if isinstance(project.get("name"), str) else None
        project_version = (
            project.get("version") if isinstance(project.get("version"), str) else None
        )
        if project_version is None and "version" in project.get("dynamic", []):
            tool = document.get("tool") if isinstance(document.get("tool"), dict) else {}
            setuptools = tool.get("setuptools") if isinstance(tool.get("setuptools"), dict) else {}
            dynamic = (
                setuptools.get("dynamic") if isinstance(setuptools.get("dynamic"), dict) else {}
            )
            version_rule = dynamic.get("version")
            version_attr = version_rule.get("attr") if isinstance(version_rule, dict) else None
            if isinstance(version_attr, str):
                project_version = _literal_module_attribute(root, version_attr)
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
        tool = document.get("tool") if isinstance(document.get("tool"), dict) else {}
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
        setuptools = tool.get("setuptools") if isinstance(tool.get("setuptools"), dict) else {}
        configured_packages = setuptools.get("packages")
        if isinstance(configured_packages, list):
            packages = [value for value in configured_packages if isinstance(value, str)]
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
        if isinstance(configured_package_data, dict):
            package_data = {
                name: [pattern for pattern in patterns if isinstance(pattern, str)]
                for name, patterns in configured_package_data.items()
                if isinstance(name, str) and isinstance(patterns, list)
            }
        package_find = (
            setuptools.get("packages", {}).get("find", {})
            if isinstance(setuptools.get("packages"), dict)
            else {}
        )
        configured_where = package_find.get("where", []) if isinstance(package_find, dict) else []
        if isinstance(configured_where, list):
            source_roots = [value for value in configured_where if isinstance(value, str)]
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
        if distribution_name is None:
            distribution_name = parser.get("metadata", "name", fallback=None)
            project_version = parser.get("metadata", "version", fallback=None)
            requires_python = parser.get("options", "python_requires", fallback=None)
        install_requires = parser.get("options", "install_requires", fallback="")
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

    setup_py_path = root / "setup.py"
    if setup_py_path.is_file():
        metadata_files.append("setup.py")
        setup_values = _literal_setup_arguments(setup_py_path)
        if distribution_name is None and isinstance(setup_values.get("name"), str):
            distribution_name = setup_values["name"]
        if project_version is None and isinstance(setup_values.get("version"), str):
            project_version = setup_values["version"]
        if requires_python is None and isinstance(setup_values.get("python_requires"), str):
            requires_python = setup_values["python_requires"]
        for specification in setup_values.get("install_requires", []):
            if not isinstance(specification, str):
                continue
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
                values = setup_entry_points.get(group, [])
                if not isinstance(values, list):
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
        if isinstance(package_dir, dict) and isinstance(package_dir.get(""), str):
            source_roots = source_roots or [package_dir[""]]

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
        if requires_python is None and isinstance(pipfile_requires.get("python_version"), str):
            requires_python = f"=={pipfile_requires['python_version']}.*"

    if not source_roots:
        source_roots = ["src"] if (root / "src").is_dir() else ["."]
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
            package_directories=package_directories,
            package_data=package_data,
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
    )
