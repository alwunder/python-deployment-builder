"""AST-based import inventory and declaration matching."""

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name

from python_deployment_builder.models import DependencyAssessment, Evidence, ImportObservation

IMPORT_NAME_OVERRIDES: dict[str, tuple[str, ...]] = {
    "beautifulsoup4": ("bs4",),
    "opencv-python": ("cv2",),
    "pillow": ("PIL",),
    "pyqt5": ("PyQt5",),
    "pyqt6": ("PyQt6",),
    "pyside6": ("PySide6",),
    "pyyaml": ("yaml",),
    "scikit-learn": ("sklearn",),
    "python-dotenv": ("dotenv",),
    "pywin32": ("win32api", "win32com", "pythoncom"),
}

EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "tests",
    "venv",
}


@dataclass(frozen=True)
class ImportScanResult:
    observations: list[ImportObservation]
    parse_errors: list[str]


def distribution_import_names(distribution: str) -> tuple[str, ...]:
    canonical = canonicalize_name(distribution)
    if canonical in IMPORT_NAME_OVERRIDES:
        return IMPORT_NAME_OVERRIDES[canonical]
    return (canonical.replace("-", "_"),)


def _source_files(root: Path, source_roots: list[str]) -> list[Path]:
    files: set[Path] = set()
    for source_root in source_roots:
        base = (root / source_root).resolve()
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if not any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(root).parts):
                files.add(path)
    return sorted(files)


def _local_modules(root: Path, source_roots: list[str]) -> set[str]:
    modules: set[str] = set()
    for source_root in source_roots:
        base = (root / source_root).resolve()
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / "__init__.py").is_file():
                modules.add(child.name)
            elif child.is_file() and child.suffix == ".py":
                modules.add(child.stem)
    return modules


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[tuple[str, int, bool]] = []
        self._optional_depth = 0

    def visit_Try(self, node: ast.Try) -> None:  # noqa: N802 - ast visitor API
        optional = any(
            handler.type is None
            or (
                isinstance(handler.type, ast.Name)
                and handler.type.id in {"ImportError", "ModuleNotFoundError"}
            )
            or (
                isinstance(handler.type, ast.Tuple)
                and any(
                    isinstance(item, ast.Name) and item.id in {"ImportError", "ModuleNotFoundError"}
                    for item in handler.type.elts
                )
            )
            for handler in node.handlers
        )
        if optional:
            self._optional_depth += 1
        for statement in node.body:
            self.visit(statement)
        if optional:
            self._optional_depth -= 1
        for statement in (*node.handlers, *node.orelse, *node.finalbody):
            self.visit(statement)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.imports.append((alias.name.split(".")[0], node.lineno, self._optional_depth > 0))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.level == 0 and node.module:
            self.imports.append((node.module.split(".")[0], node.lineno, self._optional_depth > 0))


def scan_imports(
    root: Path,
    source_roots: list[str],
    dependencies: list[DependencyAssessment],
) -> ImportScanResult:
    """Classify source imports without importing the target modules."""

    declared: dict[str, str] = {}
    for dependency in dependencies:
        for import_name in distribution_import_names(dependency.distribution_name):
            declared[import_name.lower()] = dependency.distribution_name
    local_modules = {name.lower() for name in _local_modules(root, source_roots)}
    standard_library = {name.lower() for name in sys.stdlib_module_names}
    accumulated: dict[tuple[str, str, str | None, bool], list[Evidence]] = defaultdict(list)
    parse_errors: list[str] = []

    for path in _source_files(root, source_roots):
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError) as exc:
            parse_errors.append(f"{relative}: {exc}")
            continue
        visitor = _ImportVisitor()
        visitor.visit(tree)
        lines = source.splitlines()
        for import_name, line_number, optional in visitor.imports:
            lowered = import_name.lower()
            distribution: str | None = None
            if lowered in standard_library:
                classification = "standard_library"
            elif lowered in local_modules:
                classification = "local_project"
            elif lowered in declared:
                classification = "declared_third_party"
                distribution = declared[lowered]
            else:
                classification = "observed_undeclared_third_party"
            excerpt = lines[line_number - 1].strip() if line_number <= len(lines) else None
            key = (import_name, classification, distribution, optional)
            accumulated[key].append(
                Evidence(
                    file=relative,
                    line=line_number,
                    detail="AST import statement.",
                    excerpt=excerpt,
                )
            )

    observations = [
        ImportObservation(
            import_name=key[0],
            classification=key[1],
            distribution_name=key[2],
            optional_import=key[3],
            evidence=evidence,
        )
        for key, evidence in accumulated.items()
    ]
    observations.sort(
        key=lambda item: (item.classification, item.import_name.lower(), item.optional_import)
    )
    return ImportScanResult(observations=observations, parse_errors=parse_errors)
