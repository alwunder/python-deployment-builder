"""Repository resource and dotenv discovery."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from python_deployment_builder.analysis.imports import EXCLUDED_DIRECTORIES
from python_deployment_builder.models import (
    ConfigurationRequirement,
    Evidence,
    FindingStatus,
    ResourceRequirement,
)

RESOURCE_DIRECTORIES = {
    "assets": "assets",
    "config": "configuration",
    "examples": "examples",
    "icons": "icons",
    "profiles": "profiles",
    "prompts": "prompts",
    "schemas": "schemas",
    "templates": "templates",
}
RESOURCE_FILES = {"README.md": "documentation", ".env.example": "configuration_example"}


def _literal_evidence(root: Path, source_roots: list[str]) -> dict[str, list[Evidence]]:
    found: dict[str, list[Evidence]] = defaultdict(list)
    for source_root in source_roots:
        base = (root / source_root).resolve()
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(root).parts):
                continue
            relative = path.relative_to(root).as_posix()
            try:
                source = path.read_text(encoding="utf-8-sig")
                tree = ast.parse(source, filename=relative)
            except (OSError, SyntaxError, UnicodeError):
                continue
            lines = source.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                normalized = node.value.replace("\\", "/").strip("./")
                anchor = normalized.split("/", 1)[0]
                candidates = {anchor, normalized}
                for candidate in candidates:
                    if candidate in RESOURCE_DIRECTORIES or candidate in RESOURCE_FILES:
                        found[candidate].append(
                            Evidence(
                                file=relative,
                                line=node.lineno,
                                detail=f"Resource path literal {node.value!r}.",
                                excerpt=lines[node.lineno - 1].strip(),
                            )
                        )
    return found


def inspect_resources(
    root: Path, source_roots: list[str]
) -> tuple[list[ResourceRequirement], list[ConfigurationRequirement]]:
    literals = _literal_evidence(root, source_roots)
    resources: list[ResourceRequirement] = []
    for name, kind in {**RESOURCE_DIRECTORIES, **RESOURCE_FILES}.items():
        path = root / name
        if not path.exists():
            continue
        evidence = literals.get(name, [])
        evidence.insert(
            0,
            Evidence(file=name, detail="Repository resource exists outside the import package."),
        )
        resources.append(
            ResourceRequirement(
                path=name,
                kind=kind,
                access_mode="read",
                packaging_status="repository_adjacent",
                status=FindingStatus.DETECTED if literals.get(name) else FindingStatus.INFERRED,
                evidence=evidence,
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
                    "Example dotenv file documents configuration; real .env contents must "
                    "never be copied."
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
                    "Developer dotenv file exists and must be excluded from generated "
                    "deployment metadata and copies."
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
