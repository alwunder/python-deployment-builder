"""Disposable interpreter evidence for as_file and relative import_module."""

import argparse
import ast
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import python_deployment_builder.analysis.inventory as inventory
import python_deployment_builder.analysis.resources as resources
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.validation.static import validate_static_kit

PROBE = """
import importlib, importlib.resources as resources, importlib.util, json, sys
result = {'version': sys.version.split()[0]}
for kind, target in [('file', 'model.dat'), ('directory', 'models')]:
    for spelling in ['positional', 'keyword']:
        try:
            traversable = resources.files('app') / target
            context = (resources.as_file(traversable) if spelling == 'positional'
                       else resources.as_file(traversable=traversable))
            with context as path:
                text = ((path / 'nested.dat').read_text() if kind == 'directory'
                        else path.read_text())
            result[kind + '_' + spelling] = text
        except Exception as error:
            result[kind + '_' + spelling] = type(error).__name__
result['relative'] = {}
for name, package in [('.examples.plugin', 'app'), ('..examples.plugin', 'app.sub'),
                      ('...plugin', 'app'), ('app.examples.plugin', 'other')]:
    try:
        resolved = importlib.util.resolve_name(name, package)
        value = importlib.import_module(name, package).run()
        result['relative'][name + ':' + package] = [resolved, value]
    except Exception as error:
        result['relative'][name + ':' + package] = type(error).__name__
assert result['file_positional'] == 'MODEL'
assert result['file_keyword'] == result['directory_keyword'] == 'TypeError'
assert result['relative']['.examples.plugin:app'] == ['app.examples.plugin', 42]
assert result['relative']['..examples.plugin:app.sub'] == ['app.examples.plugin', 42]
assert result['relative']['...plugin:app'] == 'ImportError'
sys.path.insert(0, 'resources.zip')
for kind, target in [('file', 'model.dat'), ('directory', 'models')]:
    try:
        with resources.as_file(resources.files('zipped') / target) as path:
            result['zip_' + kind] = ((path / 'nested.dat').read_text() if kind == 'directory'
                                    else path.read_text())
    except Exception as error:
        result['zip_' + kind] = type(error).__name__
assert result['zip_file'] == 'MODEL'
assert result['zip_directory'] == (
    'DIRECTORY' if sys.version_info >= (3,12) else 'IsADirectoryError')
print(json.dumps(result))
"""


def old_function(module, name):
    source = subprocess.check_output(
        [
            "git",
            "show",
            "0d26ebe9b536335d278fabf44477a22fa13a42c1:src/"
            + module.__name__.replace(".", "/")
            + ".py",
        ],
        text=True,
    )
    node = next(
        item
        for item in ast.parse(source).body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    namespace = dict(module.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<starting-head>", "exec"), namespace)
    return namespace[name]


def deployment_probe(root, python):
    old_literal = old_function(resources, "_literal_evidence")
    old_literal.__globals__["_resource_import_bindings"] = old_function(
        resources, "_resource_import_bindings"
    )
    old_imports = old_function(inventory, "_imported_modules")
    result = {}
    fake_uv = root / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    for kind in ["as_file", "relative_import"]:
        source = root / kind / "source"
        package = source / "src/app"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "model.dat").write_text("MODEL")
        examples = package / "examples"
        examples.mkdir()
        (examples / "__init__.py").write_text("")
        (examples / "plugin.py").write_text("def run(): return 42\n")
        (package / "main.py").write_text(
            "from importlib.resources import files, as_file\ndef main():\n"
            " with as_file(files('app') / 'model.dat') as path: return path.read_text()\n"
            if kind == "as_file"
            else "import importlib\ndef main():\n"
            " return importlib.import_module('.examples.plugin', package='app').run()\n"
        )
        (source / "pyproject.toml").write_text(
            "[project]\nname='demo'\nversion='1.0'\nrequires-python='>=3.12'\n"
            "[project.scripts]\ndemo='app.main:main'\n"
        )
        (source / "uv.lock").write_text(
            "version=1\nrevision=3\nrequires-python='>=3.12'\n"
            "[[package]]\nname='demo'\nversion='1.0'\nsource={virtual='.'}\n"
        )
        for args in [
            ("init",),
            ("add", "."),
            (
                "-c",
                "user.name=PDB Test",
                "-c",
                "user.email=pdb@example.invalid",
                "commit",
                "-m",
                "fixture",
            ),
        ]:
            subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
        for label in ["before", "after"]:
            kit = root / kind / label
            with (
                patch.object(
                    resources,
                    "_literal_evidence",
                    old_literal if label == "before" else resources._literal_evidence,
                ),
                patch.object(
                    inventory,
                    "_imported_modules",
                    old_imports if label == "before" else inventory._imported_modules,
                ),
                patch(
                    "python_deployment_builder.generation.generator.acquire_pinned_uv",
                    return_value=fake_uv,
                ),
                patch(
                    "python_deployment_builder.generation.generator.prepare_lockfile",
                    side_effect=lambda path, *args, **kw: LockPreparationResult(
                        path=path / "uv.lock", created=False, checked=True, commands=()
                    ),
                ),
            ):
                generate_deployment_kit(
                    MaterializedRepository(root=source, source=str(source), source_kind="local"),
                    kit,
                    bootstrap_mode="online_cmd",
                )
            report = validate_static_kit(kit)
            assert report.final_state.value == "STATIC_VALID"
            run = subprocess.run(
                [str(python), "-B", "-E", "-s", "-c", "from app.main import main; print(main())"],
                cwd=kit / "src",
                capture_output=True,
                text=True,
                check=False,
            )
            result[kind + "_" + label] = {
                "static": report.final_state.value,
                "exit": run.returncode,
                "result": run.stdout.strip()
                if run.returncode == 0
                else run.stderr.splitlines()[-1],
            }
            assert (run.returncode == 0) == (label == "after")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("python", type=Path, nargs="+")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pdb-resource-wrappers-") as temporary:
        root = Path(temporary)
        for relative, value in {
            "app/__init__.py": "",
            "app/model.dat": "MODEL",
            "app/models/nested.dat": "DIRECTORY",
            "app/sub/__init__.py": "",
            "app/examples/__init__.py": "",
            "app/examples/plugin.py": "def run(): return 42\n",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        with zipfile.ZipFile(root / "resources.zip", "w") as archive:
            for name, text in {
                "zipped/__init__.py": "",
                "zipped/model.dat": "MODEL",
                "zipped/models/nested.dat": "DIRECTORY",
            }.items():
                archive.writestr(name, text)
        for python in args.python:
            result = subprocess.run(
                [str(python), "-B", "-E", "-s", "-c", PROBE],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            print(result.stdout.strip())
        print(json.dumps(deployment_probe(root, args.python[-1]), indent=2))


if __name__ == "__main__":
    main()
