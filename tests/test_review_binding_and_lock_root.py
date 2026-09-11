"""Regression coverage for PR #9's alias, keyword, and legacy lock-root findings."""

import ast
import json
from types import SimpleNamespace

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.runtime_assumptions import scan_runtime_assumptions
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import configured_secret_values
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.manifest import build_deployment_manifest
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.planning.lockfile import identify_uv_lock_root_name
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.security_policy import text_security_findings
from python_deployment_builder.validation.static import _static_lock_root_name, validate_static_kit

ENV_BINDINGS = [
    ("import os", "os.getenv"),
    ("import os as operating", "operating.getenv"),
    ("from os import getenv", "getenv"),
    ("from os import getenv as read_env", "read_env"),
    ("import os", "os.environ.get"),
    ("import os as operating", "operating.environ.get"),
    ("from os import environ", "environ.get"),
    ("from os import environ as env", "env.get"),
]


def repository(root):
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def write_project(root, source):
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(source, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[project]\nname='binding-demo'\nversion='1.0'\nrequires-python='>=3.12'\n"
        "[project.scripts]\nbinding-demo='app:main'\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
        "[[package]]\nname='binding-demo'\nversion='1.0'\nsource={virtual='.'}\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(("imports", "function"), ENV_BINDINGS)
@pytest.mark.parametrize(
    "arguments",
    [
        "'DB_PASSWORD'",
        "key='DB_PASSWORD'",
        "'DB_PASSWORD', 'fallback'",
        "key='DB_PASSWORD', default='fallback'",
    ],
)
def test_environment_import_bindings(tmp_path, imports, function, arguments):
    # Imports after the function declaration still provide file-level evidence.
    (tmp_path / "app.py").write_text(
        f"def main(): return {function}({arguments})\n{imports}\n", encoding="utf-8"
    )
    result = scan_runtime_assumptions(tmp_path, ["."])
    assert [(item.name, item.secret) for item in result.configuration_requirements] == [
        ("DB_PASSWORD", True)
    ]


@pytest.mark.parametrize(
    ("imports", "receiver"),
    [
        ("import os", "os.environ"),
        ("import os as operating", "operating.environ"),
        ("from os import environ", "environ"),
        ("from os import environ as env", "env"),
    ],
)
@pytest.mark.parametrize("key", ["API-KEY", "2FA_TOKEN"])
def test_environment_alias_subscripts(tmp_path, imports, receiver, key):
    (tmp_path / "app.py").write_text(f"{imports}\nvalue={receiver}[{key!r}]\n")
    assert [
        item.name for item in scan_runtime_assumptions(tmp_path, ["."]).configuration_requirements
    ] == [key]


@pytest.mark.parametrize(
    "source",
    [
        "def getenv(key): return key\ngetenv('DB_PASSWORD')",
        "thing.getenv('DB_PASSWORD')",
        "from os import *\ngetenv('DB_PASSWORD')",
        "from .os import getenv\ngetenv('DB_PASSWORD')",
        "from os import getenv as read_env\nread_env(key=name)",
    ],
)
def test_unproven_environment_names_are_ignored(tmp_path, source):
    (tmp_path / "app.py").write_text(source)
    assert not scan_runtime_assumptions(tmp_path, ["."]).configuration_requirements


@pytest.mark.parametrize(("imports", "function"), ENV_BINDINGS[1:4] + ENV_BINDINGS[5:])
def test_alias_secret_manifest_and_scan_chain(tmp_path, monkeypatch, imports, function):
    secret = "PDBSyntheticSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    write_project(tmp_path, f"{imports}\ndef main(): return {function}(key='DB_PASSWORD')\n")
    assessment = assess_repository(repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    manifest = build_deployment_manifest(
        plan,
        tmp_path,
        bootstrap_mode="online_cmd",
        system_certs=False,
        approved_artifacts=[],
        bundled_uv_sha256=None,
        referenced_files=[],
    )
    assert manifest.configuration_secret_names == ["DB_PASSWORD"]
    assert text_security_findings(secret) == set()
    assert "configured_secret" in text_security_findings(
        secret,
        configured_secret_values=configured_secret_values(manifest.configuration_secret_names),
    )
    assert (
        secret
        not in assessment.model_dump_json() + plan.model_dump_json() + manifest.model_dump_json()
    )
    monkeypatch.setenv("DB_PASSWORD", "1234567")
    with pytest.raises(PreparationError, match="SHORT_CONFIGURED_SECRET_UNSCANNABLE") as caught:
        configured_secret_values(manifest.configuration_secret_names)
    assert "1234567" not in str(caught.value)


@pytest.mark.parametrize(
    ("imports", "function"),
    [
        ("import importlib", "importlib.import_module"),
        ("import importlib as il", "il.import_module"),
        ("from importlib import import_module", "import_module"),
        ("from importlib import import_module as load", "load"),
        ("", "__import__"),
    ],
)
def test_keyword_dynamic_import_stages_module_and_initializers(tmp_path, imports, function):
    write_project(
        tmp_path, f"{imports}\ndef main(): return {function}(name='pkg.examples.plugin')\n"
    )
    package = tmp_path / "pkg/examples"
    package.mkdir(parents=True)
    for path in ["pkg/__init__.py", "pkg/examples/__init__.py", "pkg/examples/plugin.py"]:
        (tmp_path / path).write_text("VALUE=1\n")
    assessment = assess_repository(repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    staged = _staging_files(tmp_path, assessment, plan, include=True)
    assert {"pkg/__init__.py", "pkg/examples/__init__.py", "pkg/examples/plugin.py"} <= set(staged)
    assert plan.deployment_mode == "source"


@pytest.mark.parametrize(
    ("imports", "function"),
    [
        ("import pkgutil", "pkgutil.get_data"),
        ("import pkgutil as pu", "pu.get_data"),
        ("from pkgutil import get_data", "get_data"),
        ("from pkgutil import get_data as read", "read"),
    ],
)
@pytest.mark.parametrize(
    "args",
    [
        "'pkg', 'nested/defaults.json'",
        "'pkg', resource='nested/defaults.json'",
        "package='pkg', resource='nested/defaults.json'",
    ],
)
def test_pkgutil_keywords_stage_resource(tmp_path, imports, function, args):
    write_project(tmp_path, f"{imports}\ndef main(): return {function}({args})\n")
    (tmp_path / "pkg/nested").mkdir(parents=True)
    (tmp_path / "pkg/__init__.py").write_text("")
    (tmp_path / "pkg/nested/defaults.json").write_text("{}\n")
    assessment = assess_repository(repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "pkg/nested/defaults.json" in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("kind", ["setup.py", "setup.cfg"])
@pytest.mark.parametrize("root_present", [True, False])
def test_legacy_source_kit_static_root_identity(tmp_path, monkeypatch, kind, root_present):
    source = tmp_path / "source"
    write_project(source, "def main(): return 0\n")
    (source / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools==79.0.1']\nbuild-backend='setuptools.build_meta'\n"
    )
    if kind == "setup.py":
        content = (
            "from setuptools import setup\nsetup(name='binding-demo', version='1.0', "
            "py_modules=['app'], entry_points={'console_scripts':['binding-demo=app:main']})\n"
        )
    else:
        content = (
            "[metadata]\nname=binding-demo\nversion=1.0\n[options]\npy_modules=app\n"
            "[options.entry_points]\nconsole_scripts=\n    binding-demo=app:main\n"
        )
    (source / kind).write_text(content)
    if not root_present:
        # Actual uv 0.12.5 output for both legacy metadata forms: no package table.
        (source / "uv.lock").write_text("version=1\nrevision=3\nrequires-python='>=3.12'\n")
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    if not root_present:
        plan = create_deployment_plan(assess_repository(repository(source)), repository_root=source)
        assert plan.deployment_mode == "source"
        assert "LEGACY_LOCK_ROOT_UNIDENTIFIABLE" in plan.risk_gate.blocking_codes
        assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" not in plan.risk_gate.blocking_codes
        preview = generate_deployment_kit(repository(source), kit, dry_run=True).preview
        assert any("LEGACY_LOCK_ROOT_UNIDENTIFIABLE" in item for item in preview.developer_actions)
        with pytest.raises(PreparationError, match="LEGACY_LOCK_ROOT_UNIDENTIFIABLE"):
            generate_deployment_kit(repository(source), kit, bootstrap_mode="online_cmd")
        assert not kit.exists()
        return
    generate_deployment_kit(repository(source), kit, bootstrap_mode="online_cmd")
    report = validate_static_kit(kit)
    assert report.final_state.value == "STATIC_VALID", report.model_dump_json()
    manifest = json.loads((kit / "deployment/manifest.json").read_text())
    assert manifest["deployment_mode"] == "source"
    assert manifest["application_artifact"] is None


@pytest.mark.parametrize(
    ("project", "artifact", "locked", "expected"),
    [
        ("demo", None, "demo", "demo"),
        (None, "demo", "demo", "demo"),
        (None, None, "Legacy_Demo", "Legacy_Demo"),
        ("other", None, "demo", None),
        (None, "other", "demo", None),
        ("demo", "other", "demo", None),
    ],
)
def test_staged_lock_root_identity_cross_checks(tmp_path, project, artifact, locked, expected):
    (tmp_path / "pyproject.toml").write_text(f"[project]\nname={project!r}\n" if project else "")
    (tmp_path / "uv.lock").write_text(
        f"version=1\n[[package]]\nname={locked!r}\nsource={{virtual='.'}}\n"
    )
    manifest = SimpleNamespace(
        application_artifact=(SimpleNamespace(distribution_name=artifact) if artifact else None)
    )
    assert _static_lock_root_name(tmp_path, manifest) == expected


def test_keyword_before_positional_resource_is_invalid_python():
    with pytest.raises(SyntaxError):
        ast.parse("pkgutil.get_data(package='app', 'defaults.json')")


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("import os as operating", "operating.listdir(path='bundle/assets')"),
        ("from os import scandir as scan", "scan(path='bundle/assets')"),
    ],
)
def test_directory_read_alias_audit(tmp_path, imports, call):
    write_project(tmp_path, f"{imports}\ndef main(): return {call}\n")
    (tmp_path / "bundle/assets").mkdir(parents=True)
    (tmp_path / "bundle/assets/defaults.json").write_text("{}")
    assessment = assess_repository(repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "bundle/assets/defaults.json" in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("source", ["virtual", "editable"])
def test_lock_root_preserves_exact_name(tmp_path, source):
    (tmp_path / "uv.lock").write_text(
        f"version=1\n[[package]]\nname='Legacy_Demo'\nsource={{{source}='.'}}\n"
    )
    assert identify_uv_lock_root_name(tmp_path) == "Legacy_Demo"


@pytest.mark.parametrize(
    "lock",
    [
        "version=1\n",
        "version=1\npackage=[]\n",
        "version=1\n[[package]]\nname='dependency'\nsource={editable='elsewhere'}\n",
    ],
)
def test_missing_lock_root_is_not_guessed(tmp_path, lock):
    (tmp_path / "uv.lock").write_text(lock)
    assert identify_uv_lock_root_name(tmp_path) is None


@pytest.mark.parametrize(
    "lock",
    [
        "[invalid",
        "package='wrong'",
        "package=[1]",
        "[[package]]\nname='bad/name'\nsource={virtual='.'}",
        "[[package]]\nsource={virtual='.'}",
        "[[package]]\nname='demo'\nsource={virtual='.', editable='.'}",
        "[[package]]\nname='demo'\nsource={virtual='.'}\n"
        "[[package]]\nname='other'\nsource={editable='.'}",
        "[[package]]\nname='demo'\nsource='wrong'",
    ],
)
def test_malformed_or_ambiguous_lock_roots_fail_controlled(tmp_path, lock):
    (tmp_path / "uv.lock").write_text(lock)
    with pytest.raises(ValueError):
        identify_uv_lock_root_name(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n")
    assert _static_lock_root_name(tmp_path, SimpleNamespace(application_artifact=None)) is None


@pytest.mark.parametrize(
    "name",
    ["module_name", "f'pkg.{name}'", "'.plugin'", "'pkg..plugin'", "'pkg/plugin'", "'pkg-plugin'"],
)
def test_dynamic_keyword_names_are_not_resolved(tmp_path, name):
    from python_deployment_builder.analysis.inventory import _imported_modules

    tree = ast.parse(f"import importlib\nimportlib.import_module(name={name})")
    assert _imported_modules(tree, tmp_path / "app.py", tmp_path, ["."]) == [("importlib", 1)]


@pytest.mark.parametrize(
    ("imports", "call", "category", "value"),
    [
        (
            "import subprocess as sp",
            "sp.run(args=['convert.exe'])",
            "external_executable",
            "convert.exe",
        ),
        (
            "from subprocess import run as execute",
            "execute(args=['convert.exe'])",
            "external_executable",
            "convert.exe",
        ),
        ("import ctypes as ct", "ct.CDLL(name='runtime.dll')", "native_runtime", "runtime.dll"),
        (
            "from ctypes import CDLL as load",
            "load(name='runtime.dll')",
            "native_runtime",
            "runtime.dll",
        ),
        ("from os import getcwd as cwd", "cwd()", "path_assumption", "current working directory"),
        (
            "from webbrowser import open as browse",
            "browse('https://example.org')",
            "external_launcher",
            "webbrowser.open",
        ),
    ],
)
def test_bounded_runtime_binding_audit(tmp_path, imports, call, category, value):
    (tmp_path / "app.py").write_text(f"{imports}\n{call}\n")
    result = scan_runtime_assumptions(tmp_path, ["."])
    assert any(
        item.category == category and item.name == value for item in result.runtime_requirements
    )


@pytest.mark.parametrize(
    "arguments",
    [
        "package=dynamic, resource='defaults.json'",
        "package='pkg', resource=dynamic",
        "package='pkg', resource='../defaults.json'",
        "package='pkg', resource='/defaults.json'",
        "package='pkg', resource='nested\\\\defaults.json'",
        "package='pkg', resource='defaults.json', unexpected=True",
        "'pkg', 'defaults.json', 'extra'",
    ],
)
def test_pkgutil_keyword_safety(tmp_path, arguments):
    write_project(tmp_path, f"import pkgutil\ndef main(): return pkgutil.get_data({arguments})\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text("")
    (tmp_path / "pkg/defaults.json").write_text("{}")
    assessment = assess_repository(repository(tmp_path))
    assert all(item.path != "pkg/defaults.json" for item in assessment.resources)


@pytest.mark.parametrize(
    "imports", ["from .pkgutil import get_data", "def get_data(package, resource): return None"]
)
def test_pkgutil_resource_binding_must_be_stdlib(tmp_path, imports):
    write_project(
        tmp_path,
        f"{imports}\ndef main(): return get_data(package='pkg', resource='defaults.json')\n",
    )
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text("")
    (tmp_path / "pkg/defaults.json").write_text("{}")
    assert all(
        item.path != "pkg/defaults.json"
        for item in assess_repository(repository(tmp_path)).resources
    )


@pytest.mark.parametrize("packaged", [False, True])
def test_pkgutil_duplicate_bindings_and_package_data(tmp_path, packaged):
    write_project(
        tmp_path,
        "import pkgutil\ndef main(): return pkgutil.get_data("
        "'pkg', 'defaults.json', package='wrong', resource='wrong.json')\n",
    )
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text("")
    (tmp_path / "pkg/defaults.json").write_text("{}")
    if packaged:
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text() + "[tool.setuptools]\npackages=['pkg']\n"
            "[tool.setuptools.package-data]\npkg=['defaults.json']\n"
        )
    assessment = assess_repository(repository(tmp_path))
    resource = next(item for item in assessment.resources if item.path == "pkg/defaults.json")
    assert resource.packaging_status == ("packaged" if packaged else "repository_adjacent")


def test_pkgutil_keyword_namespace_is_unresolved(tmp_path):
    write_project(
        tmp_path,
        "import pkgutil\ndef main(): return pkgutil.get_data("
        "package='pkg', resource='defaults.json')\n",
    )
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/defaults.json").write_text("{}")
    assessment = assess_repository(repository(tmp_path))
    assert all(item.path != "pkg/defaults.json" for item in assessment.resources)


@pytest.mark.parametrize(
    "reader",
    [
        "open(file='pkg/defaults.json').read()",
        "pkgutil.get_data(package='pkg', resource='defaults.json')",
    ],
)
def test_alias_secret_in_selected_resource_rejected_before_output(
    tmp_path, monkeypatch, capsys, reader
):
    source = tmp_path / "source"
    write_project(
        source,
        "from os import getenv as read_env\nimport pkgutil\n"
        f"def main():\n    read_env(key='DB_PASSWORD')\n    return {reader}\n",
    )
    (source / "pkg").mkdir()
    (source / "pkg/__init__.py").write_text("")
    secret = "PDBSyntheticSecret123"
    (source / "pkg/defaults.json").write_text(secret)
    assert text_security_findings(secret) == set()
    monkeypatch.setenv("DB_PASSWORD", secret)
    uv = tmp_path / "uv.exe"
    uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    with pytest.raises(PreparationError) as caught:
        generate_deployment_kit(repository(source), kit, bootstrap_mode="online_cmd")
    assert "SECRET" in str(caught.value)
    assert secret not in str(caught.value) + str(capsys.readouterr())
    assert not kit.exists()
