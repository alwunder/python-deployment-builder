"""Load and render package-owned Windows deployment templates."""

from __future__ import annotations

import re
from pathlib import Path

from python_deployment_builder.generation.acquisition import PreparationError

TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "templates" / "windows_uv"


def safe_windows_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9 ._-]", " ", value)
    label = re.sub(r"\s+", " ", label).strip(" .")
    return label[:80] or "Python Application"


def load_template(name: str) -> str:
    path = TEMPLATE_ROOT / name
    if path.parent != TEMPLATE_ROOT or not path.is_file():
        raise PreparationError(f"Deployment template is unavailable: {name}")
    return path.read_text(encoding="utf-8")


def render_template(name: str, values: dict[str, str]) -> bytes:
    rendered = load_template(name)
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    unresolved = sorted(set(re.findall(r"{{([A-Z0-9_]+)}}", rendered)))
    if unresolved:
        raise PreparationError(
            f"Template {name} has unresolved values: {', '.join(unresolved)}"
        )
    newline = "\r\n" if name.endswith((".bat.tmpl", ".cmd.tmpl")) else "\n"
    return (rendered.replace("\r\n", "\n").replace("\n", newline)).encode("utf-8")
