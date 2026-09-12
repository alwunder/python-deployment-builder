"""Disposable Python 3.11--3.14 functional-resource and staged-kit evidence."""

import ast
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import python_deployment_builder.analysis.resources as resources
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.validation.static import validate_static_kit

VERSIONS = ("3.11.16", "3.12.14", "3.13.15", "3.14.7")
PROBE = """
import importlib.resources as r, inspect, json, sys, warnings
warnings.simplefilter('ignore', DeprecationWarning)
result = {'version': sys.version.split()[0]}
for name in ['read_binary', 'open_binary', 'read_text', 'open_text']:
    f = getattr(r, name)
    text = name.endswith('text')
    filename = 'defaults.txt' if text else 'weights.bin'
    directory = 'templates' if text else 'models'
    cases = {
        'common': (['app', filename], {}),
        'multi': (['app', directory, filename], {'encoding':'utf-8'} if text else {}),
        'slash': (['app', directory+'/'+filename], {}),
        'old3': (['app', filename, 'utf-8'], {}),
        'old4': (['app', filename, 'utf-8', 'strict'], {}),
        'missing_encoding': (['app', directory, filename], {}),
        'deep': (['app','templates','defaults','main.txt'], {'encoding':'utf-8'}),
        'legacy_keywords': ([], {'package':'app','resource':filename}),
        'mixed_legacy': (['app'], {'resource':filename}),
        'anchor_keyword': ([], {'anchor':'app'}),
        'invented_path_keyword': ([], {'anchor':'app','path_names':filename}),
        'module_anchor': (['app.config', filename], {}),
        'top_module': (['config', filename], {}),
        'namespace_parent': (['ns.config', filename], {}),
        'package_precedence': (['app.choice', filename], {}),
    }
    outcomes = {'signature': str(inspect.signature(f))}
    for label, (args, kwargs) in cases.items():
        try:
            value = f(*args, **kwargs)
            if hasattr(value, 'read'):
                with value: value = value.read()
            outcomes[label] = value.decode() if isinstance(value, bytes) else value
        except Exception as error:
            outcomes[label] = type(error).__name__ + ': ' + str(error)
    assert outcomes['common'] == 'RESOURCE'
    modern = sys.version_info >= (3,13)
    assert (outcomes['multi'] == 'RESOURCE') == modern
    assert (outcomes['slash'] == 'RESOURCE') == modern
    assert (outcomes['module_anchor'] == 'RESOURCE') == (sys.version_info >= (3,12))
    assert (outcomes['top_module'] == 'RESOURCE') == (sys.version_info >= (3,12))
    assert (outcomes['namespace_parent'] == 'RESOURCE') == (sys.version_info >= (3,12))
    if text:
        assert (outcomes['old3'] == 'RESOURCE') == (not modern)
        assert (outcomes['old4'] == 'RESOURCE') == (not modern)
        assert (outcomes['deep'] == 'RESOURCE') == modern
    result[name] = outcomes
print(json.dumps(result))
"""


def old_resolver():
    source = subprocess.check_output(
        [
            "git",
            "show",
            "0ce99790f26e256b1cc4ab1c3879d5db70b8cb1d:"
            "src/python_deployment_builder/analysis/resources.py",
        ],
        text=True,
    )
    node = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == "_legacy_importlib_resource_path_values"
    )
    namespace = dict(resources.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<starting-head>", "exec"), namespace)
    return namespace[node.name]


def deployed_probe(root, python):
    source = root / "source"
    package = source / "src/app"
    (package / "models").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "models/weights.bin").write_bytes(b"RESOURCE")
    (package / "main.py").write_text(
        "from importlib.resources import read_binary\n"
        "def main(): return read_binary('app', 'models', 'weights.bin').decode()\n"
    )
    (source / "pyproject.toml").write_text(
        "[project]\nname='demo'\nversion='1.0'\nrequires-python='>=3.13,<3.14'\n"
        "[project.scripts]\ndemo='app.main:main'\n"
    )
    (source / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.13,<3.14'\n"
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
    fake_uv = root / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    old = old_resolver()
    for label in ("before", "after"):
        kit = root / label
        with (
            patch.object(
                resources,
                "_legacy_importlib_resource_path_values",
                old if label == "before" else resources._legacy_importlib_resource_path_values,
            ),
            patch(
                "python_deployment_builder.generation.generator.acquire_pinned_uv",
                return_value=fake_uv,
            ),
            patch(
                "python_deployment_builder.generation.generator.prepare_lockfile",
                side_effect=lambda path, *a, **kw: LockPreparationResult(
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
        run = subprocess.run(
            [str(python), "-B", "-E", "-s", "-c", "from app.main import main; print(main())"],
            cwd=kit / "src",
            capture_output=True,
            text=True,
        )
        print(
            json.dumps(
                {
                    "stage": label,
                    "static": report.final_state.value,
                    "included": (kit / "src/app/models/weights.bin").exists(),
                    "runtime": run.stdout.strip()
                    if not run.returncode
                    else run.stderr.splitlines()[-1],
                }
            ),
            flush=True,
        )
        assert report.final_state.value == "STATIC_VALID"
        assert (run.returncode == 0) == (label == "after")


def main():
    with tempfile.TemporaryDirectory(prefix="pdb-resource-families-") as directory:
        root = Path(directory)
        for package in ("app", "app/choice", "ns", ""):
            for name in ("weights.bin", "defaults.txt"):
                path = root / package / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("RESOURCE")
        for name in (
            "app/__init__.py",
            "app/config.py",
            "app/choice/__init__.py",
            "app/choice.py",
            "config.py",
            "ns/config.py",
        ):
            (root / name).write_text("")
        for name in (
            "app/models/weights.bin",
            "app/templates/defaults.txt",
            "app/templates/defaults/main.txt",
        ):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("RESOURCE")
        interpreters = [
            Path(os.environ["APPDATA"])
            / "uv/python"
            / f"cpython-{version}-windows-x86_64-none/python.exe"
            for version in VERSIONS
        ]
        for python in interpreters:
            print(
                subprocess.check_output(
                    [str(python), "-B", "-E", "-s", "-c", PROBE], cwd=root, text=True
                ),
                flush=True,
            )
        if os.environ.get("PDB_DEPLOYED_PROBE"):
            deployed_probe(root, interpreters[2])


if __name__ == "__main__":
    main()
