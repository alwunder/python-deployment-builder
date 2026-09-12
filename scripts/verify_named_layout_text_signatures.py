"""Disposable pinned setuptools discovery and legacy resource signature evidence."""

import ast
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import python_deployment_builder.analysis.metadata as metadata
from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import resolve_packaged_python_sources
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import validate_application_wheel
from python_deployment_builder.planning.planner import create_deployment_plan


def starting_inspector():
    source = subprocess.check_output(
        [
            "git",
            "show",
            "94b3fd52e3cfa2a6c4f5ebbb287b6255e291b43a:"
            "src/python_deployment_builder/analysis/metadata.py",
        ],
        text=True,
    )
    node = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == "inspect_metadata"
    )
    namespace = dict(metadata.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<starting-head>", "exec"), namespace)
    return namespace["inspect_metadata"]


def main():
    uv = sys.argv[1]
    old_inspector = starting_inspector()
    env = dict(os.environ, UV_SYSTEM_CERTS="true", UV_NO_ENV_FILE="1", UV_NO_PROGRESS="1")
    with tempfile.TemporaryDirectory(prefix="pdb-named-layout-") as temporary:
        workspace = Path(temporary)
        shapes = {
            "named": ({"app": "lib"}, ["lib/__init__.py", "lib/main.py", "lib/helpers.py"]),
            "descendants": (
                {"app": "lib"},
                ["lib/__init__.py", "lib/sub/__init__.py", "lib/sub/module.py", "lib/ns/module.py"],
            ),
            "namespace-root": ({"app": "lib"}, ["lib/main.py"]),
            "nested": (
                {"app.plugins": "vendor/plugins"},
                ["vendor/plugins/__init__.py", "vendor/plugins/sub/module.py"],
            ),
            "multiple": (
                {"app": "lib/a", "other": "lib/b"},
                ["lib/a/__init__.py", "lib/b/__init__.py"],
            ),
            "overlap": (
                {"app": "lib", "app.special": "special-src"},
                [
                    "lib/__init__.py",
                    "lib/normal/__init__.py",
                    "lib/special/__init__.py",
                    "lib/special/wrong.py",
                    "special-src/__init__.py",
                    "special-src/child/module.py",
                ],
            ),
            "missing": ({"app": "missing-lib"}, ["unrelated/__init__.py"]),
            "global": (
                {"": "lib"},
                ["lib/app/__init__.py", "lib/tests/__init__.py", "lib/helper.py"],
            ),
        }
        print(subprocess.check_output([uv, "--version"], text=True).strip())
        for kind in ("pyproject", "setup.cfg", "setup.py"):
            for shape, (mapping, members) in shapes.items():
                root = workspace / f"{kind}-{shape}"
                root.mkdir()
                for member in members:
                    path = root / member
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("def main(): return 0\n", encoding="utf-8")
                config = (
                    "[build-system]\nrequires=['setuptools==79.0.1','wheel']\n"
                    "build-backend='setuptools.build_meta'\n"
                )
                if kind == "pyproject":
                    config += (
                        "[project]\nname='mapped-demo'\nversion='1.0.0'\n"
                        "[tool.setuptools.package-dir]\n"
                    )
                    config += "".join(
                        f"{json.dumps(k)}={json.dumps(v)}\n" for k, v in mapping.items()
                    )
                elif kind == "setup.cfg":
                    (root / kind).write_text(
                        "[metadata]\nname=mapped-demo\nversion=1.0.0\n[options]\npackage_dir=\n"
                        + "".join(f"    {k} = {v}\n" for k, v in mapping.items())
                    )
                else:
                    (root / kind).write_text(
                        "from setuptools import setup\n"
                        f"setup(name='mapped-demo', version='1.0.0', package_dir={mapping!r})\n"
                    )
                (root / "pyproject.toml").write_text(config)
                before = inspect_metadata(root).project
                expected = sorted(
                    item.installed_member_path
                    for item in resolve_packaged_python_sources(root, before)
                )
                result = subprocess.run(
                    [uv, "build", "--wheel", "--python", "3.12", "--out-dir", str(root / "dist")],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                )
                wheels = list((root / "dist").glob("*.whl"))
                installed = []
                if wheels:
                    with zipfile.ZipFile(wheels[0]) as archive:
                        installed = sorted(n for n in archive.namelist() if n.endswith(".py"))
                    assert installed == expected, (kind, shape, installed, expected)
                else:
                    assert shape == "missing", result.stderr
                print(
                    json.dumps(
                        {
                            "kind": kind,
                            "shape": shape,
                            "success": result.returncode == 0,
                            "pdb_packages": before.packages,
                            "pdb_modules": before.py_modules,
                            "installed": installed,
                            "error": result.stderr[-500:] if result.returncode else None,
                        }
                    ),
                    flush=True,
                )
                if kind == "pyproject" and shape == "named":
                    # Add the authoritative launcher, then rebuild its correct wheel.
                    path = root / "pyproject.toml"
                    path.write_text(
                        path.read_text() + "[project.scripts]\nmapped-demo='app.main:main'\n"
                    )
                    (root / "uv.lock").write_text(
                        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
                        "[[package]]\nname='mapped-demo'\nversion='1.0.0'\n"
                        "source={editable='.'}\n"
                    )
                    subprocess.run(
                        [
                            uv,
                            "build",
                            "--wheel",
                            "--python",
                            "3.12",
                            "--out-dir",
                            str(root / "dist"),
                        ],
                        cwd=root,
                        env=env,
                        check=True,
                        capture_output=True,
                    )
                    repository = MaterializedRepository(
                        root=root, source=str(root), source_kind="local"
                    )
                    assessment = assess_repository(repository)
                    plan = create_deployment_plan(assessment, repository_root=root)
                    validate_application_wheel(wheels[0], assessment, plan, repository_root=root)
                    with patch(
                        "python_deployment_builder.analysis.assessor.inspect_metadata",
                        old_inspector,
                    ):
                        old_assessment = assess_repository(repository)
                    old_plan = create_deployment_plan(old_assessment, repository_root=root)
                    try:
                        validate_application_wheel(
                            wheels[0], old_assessment, old_plan, repository_root=root
                        )
                    except PreparationError as error:
                        print(
                            json.dumps(
                                {
                                    "pre_fix_correct_wheel": str(error),
                                    "post_fix_correct_wheel": "PASS",
                                }
                            ),
                            flush=True,
                        )
                    else:
                        raise AssertionError("Starting-head wrong surface accepted correct wheel")
        root = workspace / "runtime"
        (root / "app").mkdir(parents=True)
        (root / "app/__init__.py").write_text("")
        (root / "app/defaults.json").write_text("RESOURCE")
        probe = """
import importlib.resources as r, inspect, json, sys, warnings
warnings.simplefilter('ignore', DeprecationWarning)
result = {'version': sys.version.split()[0]}
for name in ['read_text', 'open_text', 'read_binary', 'open_binary']:
    f = getattr(r, name)
    records = {'signature': str(inspect.signature(f))}
    cases = [(['app','defaults.json'], {}), (['app','defaults.json','utf-8'], {}),
             (['app','defaults.json','utf-8','strict'], {}),
             (['app','defaults.json','utf-8','strict','extra'], {}),
             (['app','defaults.json','utf-8'], {'encoding':'utf-8'}),
             (['app'], {'resource':'defaults.json','encoding':'utf-8','errors':'ignore'})]
    for i, (args, kwargs) in enumerate(cases):
        try:
            value = f(*args, **kwargs)
            if hasattr(value, 'read'):
                with value: value = value.read()
            records[str(i)] = repr(value)
        except Exception as error: records[str(i)] = type(error).__name__
    result[name] = records
    assert records['0'] == ("'RESOURCE'" if name.endswith('text') else "b'RESOURCE'")
    if name.endswith('text'):
        assert records['1'] == records['2'] == records['5'] == "'RESOURCE'"
    else:
        assert records['1'] == records['2'] == records['5'] == 'TypeError'
    assert records['3'] == records['4'] == 'TypeError'
print(json.dumps(result))
"""
        for version in ("3.11.16", "3.12.14"):
            executable = (
                Path(os.environ["APPDATA"])
                / "uv/python"
                / f"cpython-{version}-windows-x86_64-none/python.exe"
            )
            print(
                subprocess.check_output([str(executable), "-B", "-c", probe], cwd=root, text=True)
            )


if __name__ == "__main__":
    main()
