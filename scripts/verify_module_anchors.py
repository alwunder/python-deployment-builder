"""Disposable direct-interpreter evidence for Python 3.12 module resource anchors."""

import argparse
import ast
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import python_deployment_builder.analysis.resources as resources
from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.generator import _staging_files
from python_deployment_builder.planning.planner import create_deployment_plan


def staging_probe(root: Path, python: Path) -> dict:
    """Compare exact starting-head anchor analysis with corrected source staging."""

    source = root / "source"
    package = source / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "config.py").write_text(
        "from importlib.resources import files\n"
        "def load(): return files('app.config').joinpath('defaults.json').read_text()\n"
    )
    (package / "defaults.json").write_text("MODULE_RESOURCE")
    (source / "pyproject.toml").write_text(
        "[project]\nname='demo'\nversion='1.0'\nrequires-python='>=3.12'\n"
        "[project.scripts]\ndemo='app.config:load'\n"
    )
    (source / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
        "[[package]]\nname='demo'\nversion='1.0'\nsource={virtual='.'}\n"
    )
    original = subprocess.check_output(
        [
            "git",
            "show",
            "2a7556358e4d909dc58a4715ef31d6850f9a9ff1:"
            "src/python_deployment_builder/analysis/resources.py",
        ],
        text=True,
    )
    node = next(
        item
        for item in ast.parse(original).body
        if isinstance(item, ast.FunctionDef) and item.name == "_resource_package_anchor_values"
    )
    namespace = dict(resources.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<starting-head>", "exec"), namespace)
    original_anchor = namespace[node.name]
    current_anchor = resources._resource_package_anchor_values
    result = {}
    for label, resolver in (
        ("before", lambda *args, allow_module_anchor=False, **kw: original_anchor(*args, **kw)),
        ("after", current_anchor),
    ):
        with patch.object(resources, "_resource_package_anchor_values", resolver):
            assessment = assess_repository(
                MaterializedRepository(root=source, source=str(source), source_kind="local")
            )
            plan = create_deployment_plan(assessment, repository_root=source)
            files = _staging_files(source, assessment, plan, include=True)
        kit = root / label
        for relative, content in files.items():
            path = kit / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        run = subprocess.run(
            [str(python), "-B", "-E", "-s", "-c", "from app.config import load; print(load())"],
            cwd=kit / "src",
            capture_output=True,
            text=True,
            check=False,
        )
        result[label] = {
            "staged": "src/app/defaults.json" in files,
            "exit": run.returncode,
            "result": run.stdout.strip() if run.returncode == 0 else run.stderr.splitlines()[-1],
        }
    assert not result["before"]["staged"]
    assert "FileNotFoundError" in result["before"]["result"]
    assert result["after"] == {"staged": True, "exit": 0, "result": "MODULE_RESOURCE"}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("python", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pdb-module-anchors-") as temporary:
        root = Path(temporary)
        for relative, content in {
            "app/__init__.py": "",
            "app/config.py": "",
            "app/defaults.json": "MODULE",
            "app/both.py": "",
            "app/both/__init__.py": "",
            "app/both/defaults.json": "PACKAGE",
            "config.py": "",
            "defaults.json": "TOP",
            "namespace/config.py": "",
            "namespace/defaults.json": "NAMESPACE",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        probe = """
import importlib, importlib.resources as resources, json, sys, warnings
result = {'version': sys.version.split()[0], 'anchors': {}}
for name in ['app', 'app.config', 'app.both', 'config', 'namespace.config']:
    entries = {}
    for spelling in ['positional', 'anchor', 'package', 'object']:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter('always')
            if spelling == 'positional':
                container = resources.files(name)
            elif spelling == 'object':
                container = resources.files(importlib.import_module(name))
            else:
                container = resources.files(**{spelling: name})
            entries[spelling] = {
                'text': container.joinpath('defaults.json').read_text(),
                'warnings': [type(item.message).__name__ for item in captured],
            }
    result['anchors'][name] = entries
print(json.dumps(result, indent=2))
"""
        result = subprocess.run(
            [str(args.python), "-B", "-c", probe],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        evidence = json.loads(result.stdout)
        assert evidence["version"] == "3.12.14"
        for name, expected in {
            "app": "MODULE",
            "app.config": "MODULE",
            "app.both": "PACKAGE",
            "config": "TOP",
            "namespace.config": "NAMESPACE",
        }.items():
            assert all(item["text"] == expected for item in evidence["anchors"][name].values())
            assert evidence["anchors"][name]["package"]["warnings"] == ["DeprecationWarning"]
        evidence["staging"] = staging_probe(root / "staging", args.python)
        print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
