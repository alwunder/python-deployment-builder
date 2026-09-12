"""AST-based detection of runtime, configuration, path, and write assumptions."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from python_deployment_builder.analysis.ast_utils import call_argument
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


def _runtime_import_bindings(tree: ast.AST) -> dict[str, str]:
    """Collect explicit imports for the already-supported stdlib runtime APIs.

    File-level evidence is intentionally independent of declaration order. This
    is not execution or lexical name resolution; wildcard/relative imports
    provide no proof. Conflicting import identities are left unresolved.
    """
    supported = {"os", "subprocess", "ctypes", "shutil", "webbrowser"}
    candidates: dict[str, set[str]] = defaultdict(set)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in supported:
                    candidates[alias.asname or alias.name].add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in supported:
            for alias in node.names:
                if alias.name != "*":
                    candidates[alias.asname or alias.name].add(f"{node.module}.{alias.name}")
    return {name: next(iter(values)) for name, values in candidates.items() if len(values) == 1}


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
        for value in ("repo_root", "_repo_root", "__file__")
    ):
        return "project_local", FindingStatus.INFERRED
    if any(value in lowered for value in ("output_dir", "destination", "selected", "run_dir")):
        return "external_user_selected", FindingStatus.INFERRED
    return "unknown", FindingStatus.NEEDS_VALIDATION


def _platforms_for(category: str, name: str) -> list[str]:
    if category == "windows_integration" or name in {
        "os.startfile",
        "ctypes.WinDLL",
        "ctypes.OleDLL",
    }:
        return ["windows"]
    if category == "external_executable" and name.lower() == "xdg-open":
        return ["linux"]
    if category == "external_executable" and name.lower() == "open":
        return ["macos"]
    if category == "external_executable" and name == "dynamic subprocess command":
        return ["unknown"]
    return ["all"]


def _simple_function_returns(tree: ast.AST) -> dict[str, str]:
    """Summarize unique module functions and direct methods by lexical identity."""

    summaries: dict[str, str] = {}
    definitions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = defaultdict(list)
    if not isinstance(tree, ast.Module):
        return summaries
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions[node.name].append(node)
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions[f"{node.name}.{member.name}"].append(member)
    for identity, nodes in definitions.items():
        if len(nodes) != 1:
            continue
        returns: list[ast.Return] = []
        pending: list[ast.AST] = list(nodes[0].body)
        while pending:
            item = pending.pop()
            if isinstance(item, ast.Return):
                returns.append(item)
                continue
            if isinstance(
                item,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            ):
                continue
            pending.extend(ast.iter_child_nodes(item))
        if len(returns) == 1 and returns[0].value is not None:
            summaries[identity] = _expression(returns[0].value)
    return summaries


class _RuntimeVisitor(ast.NodeVisitor):
    def __init__(
        self,
        relative: str,
        source_lines: list[str],
        function_returns: dict[str, str] | None = None,
        import_bindings: dict[str, str] | None = None,
    ) -> None:
        self.relative = relative
        self.lines = source_lines
        self.runtime: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
        self.config: dict[str, list[Evidence]] = defaultdict(list)
        self.writes: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
        self.assignments: dict[str, str] = {}
        self.function_returns = function_returns or {}
        self.import_bindings = import_bindings or {}
        self.lexical_scopes: list[tuple[str, str | None]] = [("module", None)]

    def _api_name(self, node: ast.AST) -> str:
        name = _qualified_name(node)
        first, separator, rest = name.partition(".")
        binding = self.import_bindings.get(first)
        return binding + separator + rest if binding is not None else ""

    def _call_summary_identity(self, function: ast.expr) -> str | None:
        if isinstance(function, ast.Name):
            return function.id
        if not isinstance(function, ast.Attribute) or not isinstance(
            function.value, ast.Name
        ):
            return None
        receiver = function.value.id
        if receiver in {"self", "cls"}:
            scope_kind, method_class = self.lexical_scopes[-1]
            if scope_kind != "function" or method_class is None:
                return None
            return f"{method_class}.{function.attr}"
        return None

    def _assigned_expression(self, value: ast.expr) -> str:
        expression = _expression(value)
        if isinstance(value, ast.Call):
            identity = self._call_summary_identity(value.func)
            if identity is not None and (returned := self.function_returns.get(identity)):
                expression = f"{expression} -> {returned}"
        return expression

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.lexical_scopes.append(("class", node.name))
        try:
            self.generic_visit(node)
        finally:
            self.lexical_scopes.pop()

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        scope_kind, scope_name = self.lexical_scopes[-1]
        method_class = scope_name if scope_kind == "class" else None
        self.lexical_scopes.append(("function", method_class))
        try:
            self.generic_visit(node)
        finally:
            self.lexical_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        self.lexical_scopes.append(("function", None))
        try:
            self.generic_visit(node)
        finally:
            self.lexical_scopes.pop()

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
        value = self._assigned_expression(node.value)
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
            value = self._assigned_expression(node.value)
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
        if self._api_name(node.value) == "os.environ":
            name = _literal_string(node.slice)
            if name:
                self.config[name].append(self._evidence(node, "Read from os.environ."))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = self._api_name(node.func) or _qualified_name(node.func)
        if self._api_name(node.func) in {"os.getenv", "os.environ.get"}:
            variable = _literal_string(
                call_argument(node, position=0, keyword="key")
            )
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
            command = _command_name(call_argument(node, position=0, keyword="args"))
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
            library = _literal_string(call_argument(node, position=0, keyword="name"))
            self._runtime("native_runtime", library or "dynamic DLL", node, f"Called {name}.")
        method = name.split(".")[-1]
        if method in WRITE_METHODS:
            if method == "open":
                mode_arguments = node.args[1:2] if name == "open" else node.args[:1]
                modes = [_literal_string(argument) for argument in mode_arguments]
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
            if name == "open":
                value = call_argument(node, position=0, keyword="file") or node
            elif name.startswith("shutil.") and len(node.args) >= 2:
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


def scan_runtime_assumptions(
    root: Path,
    source_roots: list[str],
    *,
    application_files: list[Path] | None = None,
) -> RuntimeScanResult:
    runtime: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    config: dict[str, list[Evidence]] = defaultdict(list)
    writes: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    parse_errors: list[str] = []
    files: set[Path] = set(application_files or [])
    if application_files is None:
        for source_root in source_roots:
            base = (root / source_root).resolve()
            if base.is_dir():
                files.update(
                    path
                    for path in base.rglob("*.py")
                    if not any(
                        part in EXCLUDED_DIRECTORIES for part in path.relative_to(root).parts
                    )
                )
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError) as exc:
            parse_errors.append(f"{relative}: {exc}")
            continue
        visitor = _RuntimeVisitor(
            relative,
            source.splitlines(),
            function_returns=_simple_function_returns(tree),
            import_bindings=_runtime_import_bindings(tree),
        )
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
            platforms=_platforms_for(category, name),
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
