"""AST-based detection of runtime, configuration, path, and write assumptions."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from python_deployment_builder.analysis.imports import EXCLUDED_DIRECTORIES
from python_deployment_builder.models import (
    ConfigurationRequirement,
    Evidence,
    FindingStatus,
    RuntimeRequirement,
    WriteLocation,
)

SECRET_HINTS = ("API_KEY", "TOKEN", "PASSWORD", "SECRET", "CREDENTIAL")
WRITE_METHODS = {
    "mkdir",
    "open",
    "touch",
    "write_bytes",
    "write_text",
    "copy2",
    "copyfile",
}
NETWORK_IMPORTS = {"aiohttp", "httpx", "openai", "requests", "socket", "urllib"}
GUI_IMPORTS = {
    "tkinter": "Tkinter",
    "PyQt5": "PyQt5",
    "PyQt6": "PyQt6",
    "PySide6": "PySide6",
    "webview": "pywebview",
}


@dataclass(frozen=True)
class RuntimeScanResult:
    runtime_requirements: list[RuntimeRequirement]
    configuration_requirements: list[ConfigurationRequirement]
    write_locations: list[WriteLocation]
    parse_errors: list[str]


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _command_name(node: ast.AST | None) -> str | None:
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return _literal_string(node.elts[0])
    return _literal_string(node)


def _expression(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive for future AST nodes
        return type(node).__name__


def _write_classification(expression: str) -> tuple[str, FindingStatus]:
    lowered = expression.lower()
    if "tempfile" in lowered or "gettempdir" in lowered:
        return "temporary", FindingStatus.INFERRED
    if "localappdata" in lowered or "appdata" in lowered or "user_data" in lowered:
        return "user_local", FindingStatus.INFERRED
    if any(
        value in lowered
        for value in ("repo_root", "_repo_root", "__file__", "request_cache", "cache")
    ):
        return "project_local", FindingStatus.INFERRED
    if any(value in lowered for value in ("output_dir", "destination", "selected", "run_dir")):
        return "external_user_selected", FindingStatus.INFERRED
    return "unknown", FindingStatus.NEEDS_VALIDATION


class _RuntimeVisitor(ast.NodeVisitor):
    def __init__(self, relative: str, source_lines: list[str]) -> None:
        self.relative = relative
        self.lines = source_lines
        self.runtime: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
        self.config: dict[str, list[Evidence]] = defaultdict(list)
        self.writes: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
        self.assignments: dict[str, str] = {}

    def _evidence(self, node: ast.AST, detail: str) -> Evidence:
        line = getattr(node, "lineno", None)
        excerpt = self.lines[line - 1].strip() if line and line <= len(self.lines) else None
        return Evidence(file=self.relative, line=line, detail=detail, excerpt=excerpt)

    def _runtime(self, category: str, name: str, node: ast.AST, detail: str) -> None:
        self.runtime[(category, name)].append(self._evidence(node, detail))

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            root_name = alias.name.split(".")[0]
            if root_name in GUI_IMPORTS:
                self._runtime("gui_toolkit", GUI_IMPORTS[root_name], node, "Imported GUI toolkit.")
            if root_name in NETWORK_IMPORTS:
                self._runtime("network", root_name, node, "Imported network/API module.")
            if root_name == "subprocess":
                self._runtime("subprocess", "subprocess", node, "Imported subprocess module.")
            if root_name == "ctypes":
                self._runtime("native_runtime", "DLL loading", node, "Imported ctypes.")
            if root_name == "winreg":
                self._runtime("windows_integration", "Windows registry", node, "Imported winreg.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.level == 0 and node.module:
            root_name = node.module.split(".")[0]
            if root_name in GUI_IMPORTS:
                self._runtime("gui_toolkit", GUI_IMPORTS[root_name], node, "Imported GUI toolkit.")
            if root_name in NETWORK_IMPORTS:
                self._runtime("network", root_name, node, "Imported network/API module.")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if node.id == "__file__":
            self._runtime(
                "path_assumption",
                "repository-root derived from __file__",
                node,
                "Source path participates in runtime path construction.",
            )

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        value = _expression(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = _qualified_name(target)
            else:
                continue
            self.assignments[target_name] = value
            if (
                "output_dir" in target_name.lower()
                and ("repo_root" in value.lower() or "__file__" in value.lower())
                and "outputs" in value.lower()
            ):
                expression = f"{target_name} = {value}"
                self.writes[(expression, "project_local")].append(
                    self._evidence(node, "Repository-local default output location.")
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            value = _expression(node.value)
            if isinstance(node.target, ast.Name):
                self.assignments[node.target.id] = value
            elif isinstance(node.target, ast.Attribute):
                self.assignments[_qualified_name(node.target)] = value
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str):
            value = node.value
            if re.match(r"(?i)^[a-z]:[\\/]", value):
                self._runtime("path_assumption", "hard-coded absolute path", node, value)
            if "Program Files" in value:
                self._runtime("permissions", "Program Files path", node, value)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        if _qualified_name(node.value) == "os.environ":
            name = _literal_string(node.slice)
            if name:
                self.config[name].append(self._evidence(node, "Read from os.environ."))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _qualified_name(node.func)
        if name in {"os.getenv", "os.environ.get"} and node.args:
            variable = _literal_string(node.args[0])
            if variable:
                self.config[variable].append(self._evidence(node, f"Read through {name}."))
        if name in {"Path.cwd", "pathlib.Path.cwd", "os.getcwd"}:
            self._runtime(
                "path_assumption",
                "current working directory",
                node,
                f"Called {name}.",
            )
        if name.startswith("subprocess.") and name.split(".")[-1] in {
            "call",
            "check_call",
            "check_output",
            "Popen",
            "run",
        }:
            command = _command_name(node.args[0]) if node.args else None
            self._runtime(
                "external_executable",
                command or "dynamic subprocess command",
                node,
                f"Called {name}.",
            )
        if name in {
            "os.startfile",
            "webbrowser.open",
            "webbrowser.open_new",
            "webbrowser.open_new_tab",
        }:
            self._runtime("external_launcher", name, node, f"Called {name}.")
        if name in {"ctypes.CDLL", "ctypes.WinDLL", "ctypes.OleDLL"}:
            library = _literal_string(node.args[0]) if node.args else None
            self._runtime("native_runtime", library or "dynamic DLL", node, f"Called {name}.")
        method = name.split(".")[-1]
        if method in WRITE_METHODS:
            if method == "open":
                modes = [_literal_string(argument) for argument in node.args[:1]]
                modes.extend(
                    _literal_string(keyword.value)
                    for keyword in node.keywords
                    if keyword.arg == "mode"
                )
                if not modes or not any(
                    mode and any(flag in mode for flag in "wax+") for mode in modes
                ):
                    self.generic_visit(node)
                    return
            if name.startswith("shutil.") and len(node.args) >= 2:
                value = node.args[1]
            else:
                value = node.func.value if isinstance(node.func, ast.Attribute) else node
            expression = _expression(value)
            if expression in self.assignments:
                expression = f"{expression} = {self.assignments[expression]}"
            classification, status = _write_classification(expression)
            self.writes[(expression, classification)].append(
                self._evidence(node, f"Potential write operation: {name} ({status.value}).")
            )
        self.generic_visit(node)


def scan_runtime_assumptions(root: Path, source_roots: list[str]) -> RuntimeScanResult:
    runtime: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    config: dict[str, list[Evidence]] = defaultdict(list)
    writes: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    parse_errors: list[str] = []
    files: set[Path] = set()
    for source_root in source_roots:
        base = (root / source_root).resolve()
        if base.is_dir():
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
        except (OSError, SyntaxError, UnicodeError) as exc:
            parse_errors.append(f"{relative}: {exc}")
            continue
        visitor = _RuntimeVisitor(relative, source.splitlines())
        visitor.visit(tree)
        for key, evidence in visitor.runtime.items():
            runtime[key].extend(evidence)
        for key, evidence in visitor.config.items():
            config[key].extend(evidence)
        for key, evidence in visitor.writes.items():
            writes[key].extend(evidence)

    runtime_requirements = [
        RuntimeRequirement(
            category=category,
            name=name,
            description=_runtime_description(category, name),
            status=FindingStatus.DETECTED,
            optional=None,
            evidence=evidence,
        )
        for (category, name), evidence in runtime.items()
    ]
    runtime_requirements.sort(key=lambda item: (item.category, item.name.lower()))
    configuration = [
        ConfigurationRequirement(
            name=name,
            kind="environment_variable",
            secret=any(hint in name.upper() for hint in SECRET_HINTS),
            required_at_launch=None,
            description=(
                "Environment variable is read by application source; timing/necessity requires "
                "validation."
            ),
            status=FindingStatus.DETECTED,
            evidence=evidence,
        )
        for name, evidence in sorted(config.items())
    ]
    write_locations = [
        WriteLocation(
            path_expression=expression,
            classification=classification,
            description="AST found a filesystem write-capable operation at this expression.",
            status=(
                FindingStatus.NEEDS_VALIDATION
                if classification == "unknown"
                else FindingStatus.INFERRED
            ),
            evidence=evidence,
        )
        for (expression, classification), evidence in writes.items()
    ]
    write_locations.sort(key=lambda item: (item.classification, item.path_expression))
    return RuntimeScanResult(runtime_requirements, configuration, write_locations, parse_errors)


def _runtime_description(category: str, name: str) -> str:
    descriptions = {
        "gui_toolkit": (
            f"Application source uses {name}; availability must be verified in the managed runtime."
        ),
        "network": (
            f"Application source uses {name}, indicating network or remote-service behavior."
        ),
        "subprocess": "Application source can create child processes.",
        "external_executable": f"Application may invoke external command {name!r}.",
        "external_launcher": f"Application delegates opening a path/URL through {name}.",
        "native_runtime": f"Application may load native runtime component {name!r}.",
        "windows_integration": f"Application uses Windows integration: {name}.",
        "path_assumption": f"Application has a runtime path assumption: {name}.",
        "permissions": f"Application references a permission-sensitive location: {name}.",
    }
    return descriptions.get(category, f"Detected runtime assumption: {name}.")
