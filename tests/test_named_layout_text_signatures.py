"""Named automatic layouts and legacy resource positional text parameters."""

import json

import pytest
from test_as_file_relative_imports import offline_tools  # noqa: F401
from test_dependency_authority import assess
from test_files_package_keyword import resource_project
from test_generation import _make_application_wheel, _rewrite_application_wheel

from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.module_resolution import module_locations
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import (
    resolve_package_data_members,
    resolve_packaged_python_sources,
)
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import validate_application_wheel
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.planning.planner import create_deployment_plan


def mapped_project(root, mapping=None, members=None, legacy=None):
    mapping = mapping or {"app": "lib"}
    members = members or ["lib/__init__.py", "lib/main.py", "lib/helpers.py"]
    for member in members:
        path = root / member
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("def main(): return 0\n")
    configuration = (
        "[build-system]\nrequires=['setuptools==79.0.1','wheel']\n"
        "build-backend='setuptools.build_meta'\n"
        "[project]\nname='mapped-demo'\nversion='1.0.0'\nrequires-python='>=3.12'\n"
        "[project.scripts]\nmapped-demo='app.main:main'\n"
    )
    if legacy == "setup.cfg":
        (root / legacy).write_text(
            "[options]\npackage_dir=\n" + "".join(f"    {k} = {v}\n" for k, v in mapping.items())
        )
    elif legacy == "setup.py":
        (root / legacy).write_text(
            f"from setuptools import setup\nsetup(package_dir={mapping!r})\n"
        )
    else:
        configuration += "[tool.setuptools.package-dir]\n" + "".join(
            f"{json.dumps(k)}={json.dumps(v)}\n" for k, v in mapping.items()
        )
    (root / "pyproject.toml").write_text(configuration)
    (root / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n[[package]]\nname='mapped-demo'\nversion='1.0.0'\nsource={editable='.'}\n"
    )


@pytest.mark.parametrize("legacy", [None, "setup.cfg", "setup.py"])
def test_named_mapping_establishes_installed_root(tmp_path, legacy):
    mapped_project(tmp_path, legacy=legacy)
    project = inspect_metadata(tmp_path).project
    assert project.package_directories == {"app": "lib"}
    assert project.packages == ["app"]


@pytest.mark.parametrize("function", ["read_text", "open_text"])
@pytest.mark.parametrize(
    "arguments", ["'app', 'defaults.json', 'utf-8'", "'app', 'defaults.json', 'utf-8', 'strict'"]
)
def test_positional_text_arguments_retain_resource(tmp_path, function, arguments):
    path = resource_project(tmp_path, "", "unused")
    (tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import {function}\ndef main(): return {function}({arguments})\n"
    )
    assessment = assess(tmp_path)
    assert path in {item.path for item in assessment.resources}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert path in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize(
    ("mapping", "members", "packages"),
    [
        ({"": "src"}, ["src/app/__init__.py"], ["app"]),
        (
            {"": "lib"},
            ["lib/app/__init__.py", "lib/tests/__init__.py", "lib/helper.py"],
            ["app", "tests"],
        ),
        ({"app": "lib"}, ["lib/main.py"], ["app"]),
        (
            {"app": "lib"},
            ["lib/__init__.py", "lib/sub/__init__.py", "lib/sub/module.py", "lib/ns/module.py"],
            ["app", "app.ns", "app.sub"],
        ),
        (
            {"app.plugins": "vendor/plugins"},
            ["vendor/plugins/__init__.py", "vendor/plugins/sub/module.py"],
            ["app.plugins", "app.plugins.sub"],
        ),
        (
            {"app": "lib/a", "other": "lib/b"},
            ["lib/a/__init__.py", "lib/b/__init__.py"],
            ["app", "other"],
        ),
        (
            {"app": "lib", "app.special": "special-src"},
            [
                "lib/__init__.py",
                "lib/normal/__init__.py",
                "lib/special/__init__.py",
                "lib/special/wrong.py",
                "special-src/__init__.py",
                "special-src/child/module.py",
            ],
            ["app", "app.normal", "app.special", "app.special.child"],
        ),
        (
            {"app": "lib", "other": "lib"},
            ["lib/__init__.py", "lib/sub/module.py"],
            ["app", "app.sub", "other", "other.sub"],
        ),
    ],
)
@pytest.mark.parametrize("legacy", [None, "setup.cfg", "setup.py"])
def test_named_layout_matrix(tmp_path, mapping, members, packages, legacy):
    mapped_project(tmp_path, mapping, members, legacy)
    metadata = inspect_metadata(tmp_path)
    assert not metadata.setuptools_surface_unresolved
    assert metadata.project.packages == packages
    surface = resolve_packaged_python_sources(tmp_path, metadata.project)
    assert all(
        item.installed_member_path.startswith(("app/", "other/", "tests/", "helper.py"))
        for item in surface
    )
    if "app.special" in mapping:
        assert "app/special/wrong.py" not in {item.installed_member_path for item in surface}
        assert "app/special/child/module.py" in {item.installed_member_path for item in surface}
    if mapping == {"": "lib"}:
        assert metadata.project.py_modules == ["helper"]


@pytest.mark.parametrize("directory", ["missing-lib", "../external"])
def test_invalid_named_root_never_falls_back(tmp_path, directory):
    mapped_project(tmp_path, {"app": directory}, ["unrelated/__init__.py"])
    metadata = inspect_metadata(tmp_path)
    assert metadata.project.packages == []
    assert metadata.setuptools_surface_unresolved or metadata.setuptools_external_packaging_roots
    plan = create_deployment_plan(assess(tmp_path), repository_root=tmp_path)
    assert plan.deployment_mode_condition != "PACKAGE_SURFACE_PROVEN"


@pytest.mark.parametrize("selection", ["packages=[]", "py-modules=[]", "packages=['app']"])
def test_named_mapping_does_not_override_explicit_selection(tmp_path, selection):
    mapped_project(tmp_path, members=["lib/__init__.py", "lib/sub/module.py"])
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().replace(
            "[tool.setuptools.package-dir]",
            f"[tool.setuptools]\n{selection}\n[tool.setuptools.package-dir]",
        )
    )
    assert inspect_metadata(tmp_path).project.packages == (
        ["app"] if "['app']" in selection else []
    )


@pytest.mark.parametrize("data_key", ["app", "*"])
@pytest.mark.parametrize("exclude", [False, True])
def test_named_package_data_and_wheel_completeness(tmp_path, data_key, exclude):
    source = tmp_path / "source"
    mapped_project(source)
    data = source / "lib/data"
    data.mkdir()
    for name in ("a", "b"):
        (data / f"{name}.json").write_text("{}")
    path = source / "pyproject.toml"
    path.write_text(
        path.read_text()
        + f"[tool.setuptools.package-data]\n'{data_key}'=['data/*.json']\n"
        + ("[tool.setuptools.exclude-package-data]\napp=['data/b.json']\n" if exclude else "")
    )
    assessment = assess(source)
    assert assessment.project.packages == ["app", "app.data"]
    data_members = resolve_package_data_members(source, assessment.project)
    expected = {"app/data/a.json"} | (set() if exclude else {"app/data/b.json"})
    assert {item.installed_member_path for item in data_members} == expected
    assert module_locations(source, "app.helpers", [], assessment.project.package_directories) == [
        source / "lib/helpers"
    ]
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(
        tmp_path,
        name="mapped-demo",
        version="1.0.0",
        package="app",
        target="app.main:main",
        entry_group="console_scripts",
        entry_name="mapped-demo",
        requires_python=">=3.12",
    )
    _rewrite_application_wheel(
        wheel,
        removals={"app/view.html"},
        additions={
            "app/helpers.py": "def helper(): return 0\n",
            **{name: "{}" for name in expected},
        },
    )
    validate_application_wheel(wheel, assessment, plan, repository_root=source)
    _rewrite_application_wheel(wheel, removals={"app/helpers.py"})
    with pytest.raises(PreparationError):
        validate_application_wheel(wheel, assessment, plan, repository_root=source)
    _rewrite_application_wheel(
        wheel, additions={"app/helpers.py": ""}, removals={"app/data/a.json"}
    )
    with pytest.raises(PreparationError):
        validate_application_wheel(wheel, assessment, plan, repository_root=source)


def test_named_mapping_preserves_source_mode_and_imports(tmp_path):
    # A mapping alone does not force package mode when physical imports agree.
    mapped_project(tmp_path, {"app": "app"}, ["app/__init__.py", "app/main.py", "app/helpers.py"])
    (tmp_path / "app/main.py").write_text("import app.helpers\ndef main(): return 0\n")
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert plan.deployment_mode == "source"
    assert plan.deployment_mode_condition == "SOURCE_COMPATIBLE"
    assert "app/helpers.py" in _staging_files(tmp_path, assessment, plan, include=True)


def test_named_mapping_renamed_entry_still_requires_package_mode(tmp_path):
    mapped_project(tmp_path)
    plan = create_deployment_plan(assess(tmp_path), repository_root=tmp_path)
    assert plan.deployment_mode == "package"
    assert plan.deployment_mode_condition == "ENTRYPOINT_REQUIRES_PACKAGE_MODE"


def test_named_mapping_excludes_finder_reserved_descendants(tmp_path):
    mapped_project(
        tmp_path,
        members=[
            "lib/__init__.py",
            "lib/ez_setup/module.py",
            "lib/__pycache__/module.py",
            "lib/sub/module.py",
        ],
    )
    assert inspect_metadata(tmp_path).project.packages == ["app", "app.sub"]


def test_external_mapping_cannot_leave_partial_authoritative_surface(tmp_path):
    mapped_project(tmp_path, {"app": "lib", "other": "../external"})
    metadata = inspect_metadata(tmp_path)
    assert metadata.setuptools_external_packaging_roots == ["../external"]
    assert metadata.project.packages == []


def test_global_and_named_mapping_select_explicit_layout_first(tmp_path):
    mapped_project(
        tmp_path,
        {"": "src", "app": "lib"},
        ["src/unrelated/__init__.py", "src/loose.py", "lib/__init__.py"],
    )
    project = inspect_metadata(tmp_path).project
    assert project.packages == ["app"]
    assert project.py_modules == []


@pytest.mark.parametrize("function", ["read_text", "open_text"])
@pytest.mark.parametrize("binding", ["module", "module_alias", "direct", "direct_alias"])
@pytest.mark.parametrize(
    "arguments",
    [
        "'app', 'defaults.json'",
        "'app', 'defaults.json', 'utf-8'",
        "'app', 'defaults.json', 'utf-8', 'ignore'",
        "'app', 'defaults.json', encoding=selected_encoding, errors=selected_errors",
        "package='app', resource='defaults.json', encoding=selected_encoding",
        "'app', resource='defaults.json', encoding='utf-8', errors='strict'",
    ],
)
def test_text_signature_alias_matrix(tmp_path, function, binding, arguments):
    imports, target = {
        "module": ("import importlib.resources", f"importlib.resources.{function}"),
        "module_alias": ("import importlib.resources as r", f"r.{function}"),
        "direct": (f"from importlib.resources import {function}", function),
        "direct_alias": (f"from importlib.resources import {function} as load", "load"),
    }[binding]
    path = resource_project(tmp_path, "", "unused")
    (tmp_path / "src/app/main.py").write_text(
        f"{imports}\ndef main(): return {target}({arguments})\n"
    )
    assert path in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_text", "open_text"])
@pytest.mark.parametrize(
    "arguments",
    [
        "'app', 'defaults.json', 'utf-8', encoding='ascii'",
        "'app', 'defaults.json', 'utf-8', 'strict', errors='ignore'",
        "'app', 'defaults.json', 'utf-8', 'strict', 'extra'",
        "'app', 'defaults.json', unknown=True",
        "'app', '../defaults.json', 'utf-8'",
        "'app', 'nested/defaults.json', 'utf-8'",
        "'app', resource_variable, 'utf-8'",
        "package_variable, 'defaults.json', 'utf-8'",
    ],
)
def test_invalid_text_calls_are_unresolved(tmp_path, function, arguments):
    path = resource_project(tmp_path, "", "unused")
    (tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import {function}\ndef main(): return {function}({arguments})\n"
    )
    assert path not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_binary", "open_binary"])
@pytest.mark.parametrize(
    "tail", ["", ", 'utf-8'", ", 'utf-8', 'strict'", ", encoding='utf-8'", ", unknown=True"]
)
def test_binary_signatures_remain_separate(tmp_path, function, tail):
    path = resource_project(tmp_path, "", "unused")
    (tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import {function}\n"
        f"def main(): return {function}('app', 'defaults.json'{tail})\n"
    )
    assert (path in {item.path for item in assess(tmp_path).resources}) == (not tail)


@pytest.mark.parametrize("function", ["read_text", "open_text"])
def test_unrelated_text_function_unresolved(tmp_path, function):
    path = resource_project(tmp_path, "", "unused")
    (tmp_path / "src/app/main.py").write_text(
        f"def {function}(*args): pass\n"
        f"def main(): return {function}('app', 'defaults.json', 'utf-8')\n"
    )
    assert path not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_text", "open_text"])
@pytest.mark.usefixtures("offline_tools")
def test_positional_text_release_security(tmp_path, monkeypatch, function):
    source = tmp_path / "source"
    path = resource_project(source, "", "unused")
    (source / "src/app/main.py").write_text(
        f"from importlib.resources import {function}\nfrom os import getenv\n"
        "PASSWORD=getenv('DB_PASSWORD')\n"
        f"def main(): return {function}('app', 'defaults.json', 'utf-8')\n"
    )
    secret = "PDBPositionalTextSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    (source / path).write_text(secret)
    with pytest.raises(PreparationError, match="NO_SECRET_VALUES") as error:
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            tmp_path / "kit",
        )
    assert secret not in str(error.value)
    assert not (tmp_path / "kit").exists()
