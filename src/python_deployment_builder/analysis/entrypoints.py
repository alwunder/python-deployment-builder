"""Diagnostic-only entry-point candidate discovery."""

from __future__ import annotations

import ast
from pathlib import Path

from python_deployment_builder.models import EntryPointCandidate, Evidence


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    left, right = test.left, test.comparators[0]
    return (
        isinstance(test.ops[0], ast.Eq)
        and isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(test.ops[0], ast.Eq)
        and isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return f"{call.func.value.id}.{call.func.attr}"
    return None


def _module_path(root: Path, module: str) -> Path | None:
    relative = Path(*module.split("."))
    for path in (
        root / relative.with_suffix(".py"),
        root / relative / "__init__.py",
        root / "src" / relative.with_suffix(".py"),
        root / "src" / relative / "__init__.py",
    ):
        if path.is_file():
            return path
    return None


def _likely_kind(root: Path, path: Path, target: str | None, source: str) -> str:
    texts = [source.lower()]
    if target and ":" in target:
        target_path = _module_path(root, target.split(":", 1)[0])
        if target_path:
            texts.append(target_path.read_text(encoding="utf-8-sig", errors="replace").lower())
    combined = "\n".join(texts)
    if any(token in combined for token in ("import tkinter", "from tkinter", "tk.tk(", "webview.")):
        return "gui"
    if any(token in combined for token in ("argparse", "click.", "typer.")):
        return "cli"
    return "unknown"


def detect_entry_point_candidates(
    root: Path, application_files: list[Path]
) -> list[EntryPointCandidate]:
    """Detect likely launch scripts without promoting them to deployment authority."""

    candidates: list[EntryPointCandidate] = []
    readmes = [path for path in (root / "README.md", root / "README.rst") if path.is_file()]
    for path in application_files:
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            continue
        imports: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{node.module}:{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name
        calls: list[tuple[ast.Call, str]] = []
        for node in tree.body:
            if not isinstance(node, ast.If) or not _is_main_guard(node.test):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and (name := _call_name(child)):
                    if name in {"SystemExit", "exit", "sys.exit"}:
                        continue
                    calls.append((child, name))
        if not calls:
            continue
        calls.sort(
            key=lambda item: (
                item[1].split(".")[-1].lower() not in {"main", "app", "cli", "run"},
                item[0].lineno,
            )
        )
        call, called_name = calls[0]
        target = imports.get(called_name)
        if target is None and "." in called_name:
            imported = imports.get(called_name.split(".", 1)[0])
            if imported and ":" not in imported:
                target = f"{imported}:{called_name.split('.', 1)[1]}"
        if target is None and called_name.isidentifier():
            module_path = relative.removesuffix(".py")
            if module_path.startswith("src/"):
                module_path = module_path.removeprefix("src/")
            module = module_path.replace("/", ".")
            target = f"{module}:{called_name}"
        evidence = [
            Evidence(
                file=relative,
                line=call.lineno,
                detail=f"__main__ guard invokes {called_name}().",
                excerpt=source.splitlines()[call.lineno - 1].strip(),
            )
        ]
        for readme in readmes:
            text = readme.read_text(encoding="utf-8-sig", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if path.name.lower() in line.lower():
                    evidence.append(
                        Evidence(
                            file=readme.relative_to(root).as_posix(),
                            line=number,
                            detail="Documentation references this launcher script.",
                            excerpt=line.strip(),
                        )
                    )
                    break
        root_launcher = path.parent == root
        documented = len(evidence) > 1
        package_main = path.name == "__main__.py"
        product_name_hint = any(
            token in path.stem.lower() for token in ("app", "cli", "gui", "launch", "main", "run")
        )
        likely_kind = _likely_kind(root, path, target, source)
        if target and (documented or (root_launcher and likely_kind == "gui")):
            confidence = "high"
        elif target and (package_main or product_name_hint):
            confidence = "medium"
        else:
            confidence = "low"
        candidates.append(
            EntryPointCandidate(
                path=relative,
                target=target,
                kind=likely_kind,
                confidence=confidence,
                authoritative=False,
                evidence=evidence,
            )
        )
    return sorted(candidates, key=lambda item: (item.confidence != "high", item.path.lower()))
