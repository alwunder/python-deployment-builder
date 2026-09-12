"""Functional resource reads share bounded Python 3.11--3.14 signature evidence."""

import ast
import subprocess
from pathlib import Path

import pytest
from test_as_file_relative_imports import offline_tools  # noqa: F401
from test_dependency_authority import assess
from test_files_package_keyword import resource_project
from test_planning import _write_mode_project

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import _functional_resource_call
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.planning.planner import create_deployment_plan


def functional_project(
    root,
    function="read_binary",
    arguments="'app', 'models', 'weights.bin'",
    relative="models/weights.bin",
    imports=None,
):
    resource_project(root, "", "unused")
    path = root / "src/app" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("RESOURCE")
    (root / "src/app/main.py").write_text(
        (imports or f"from importlib.resources import {function}")
        + f"\ndef main(): return {function}({arguments})\n"
    )
    return path.relative_to(root).as_posix()


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
def test_multipath_promoted_and_staged(tmp_path, function):
    arguments = "'app', 'models', 'weights.bin'"
    if function.endswith("text"):
        arguments += ", encoding='utf-8'"
    relative = functional_project(tmp_path, function, arguments)
    assessment = assess(tmp_path)
    assert relative in {item.path for item in assessment.resources}
    roles = {item.path: item.role.value for item in assessment.file_inventory}
    assert roles[relative] == "runtime_resource"
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize("binding", ["module", "module_alias", "direct", "direct_alias"])
@pytest.mark.parametrize("components", ["'models', 'weights.bin'", "'models/weights.bin'"])
def test_multipath_aliases_and_slash(tmp_path, function, binding, components):
    imports, target = {
        "module": ("import importlib.resources", f"importlib.resources.{function}"),
        "module_alias": ("import importlib.resources as r", f"r.{function}"),
        "direct": (f"from importlib.resources import {function}", function),
        "direct_alias": (f"from importlib.resources import {function} as load", "load"),
    }[binding]
    arguments = f"'app', {components}"
    if function.endswith("text"):
        arguments += ", encoding=selected_encoding, errors=selected_errors"
    relative = functional_project(tmp_path, target, arguments, imports=imports)
    assessment = assess(tmp_path)
    assert relative in {item.path for item in assessment.resources}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize("depth", [1, 3, 8])
def test_arbitrary_depth_and_static_components(tmp_path, function, depth):
    parts = [f"dir{index}" for index in range(depth)] + ["data.txt"]
    relative = "/".join(parts)
    arguments = "'app', PREFIX, " + ", ".join(repr(part) for part in parts[1:])
    if function.endswith("text"):
        arguments += ", encoding=encoding_choice"
    path = functional_project(
        tmp_path,
        function,
        arguments,
        relative,
        f"from importlib.resources import {function}\nPREFIX={parts[0]!r}",
    )
    assert path in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_text", "open_text"])
@pytest.mark.parametrize(
    ("arguments", "family", "paths"),
    [
        ("'app', 'defaults.txt'", "common", ["defaults.txt"]),
        ("'app', 'defaults.txt', 'utf-8'", "legacy_direct", ["defaults.txt"]),
        ("'app', 'defaults.txt', 'utf-8', 'strict'", "legacy_direct", ["defaults.txt"]),
        ("'app', 'defaults.txt', encoding=choice", "common", ["defaults.txt"]),
        (
            "'app', 'templates', 'defaults.txt', encoding=choice",
            "multipath",
            ["templates", "defaults.txt"],
        ),
        (
            "'app', 'templates', 'defaults', 'main.txt', encoding=choice",
            "multipath",
            ["templates", "defaults", "main.txt"],
        ),
        (
            "package='app', resource='defaults.txt', encoding=choice",
            "legacy_direct",
            ["defaults.txt"],
        ),
    ],
)
def test_text_families_are_disjoint(tmp_path, function, arguments, family, paths):
    node = ast.parse(f"{function}({arguments})", mode="eval").body
    result = _functional_resource_call(node, function)
    assert result.signature_family == family
    assert [ast.literal_eval(n) for n in result.path_nodes] == paths
    # Each family selects exactly one identity; old encoding never becomes a path.
    relative = functional_project(tmp_path, function, arguments, "/".join(paths))
    assert relative in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_text", "open_text"])
def test_missing_encoding_does_not_promote_multipath_directory(tmp_path, function):
    relative = functional_project(tmp_path, function, "'app', 'models', 'weights.bin'")
    assessment = assess(tmp_path)
    assert not any(item.path in {relative, "src/app/models"} for item in assessment.resources)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative not in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize(
    "parts",
    [
        "unknown, 'weights.bin'",
        "f'{unknown}', 'weights.bin'",
        "'models', unknown",
        "'../models', 'weights.bin'",
        "'/models', 'weights.bin'",
        "'C:models', 'weights.bin'",
        "r'models\\nested', 'weights.bin'",
        "'', 'weights.bin'",
        "'.', 'weights.bin'",
        "'models//nested', 'weights.bin'",
        "'models', '..', 'weights.bin'",
    ],
)
def test_unsafe_and_dynamic_components_unresolved(tmp_path, function, parts):
    arguments = f"'app', {parts}" + (", encoding='utf-8'" if function.endswith("text") else "")
    relative = functional_project(tmp_path, function, arguments)
    assert relative not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize(
    "arguments",
    [
        "anchor='app'",
        "anchor='app', resource='weights.bin'",
        "anchor='app', path_names='models/weights.bin'",
        "'app', 'models', unknown=True",
        "'app', 'models', **kwargs",
        "'app', *parts",
        "'app', 'models', anchor='other'",
    ],
)
def test_invalid_functional_keyword_shapes(tmp_path, function, arguments):
    relative = functional_project(tmp_path, function, arguments)
    assert relative not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize(
    "arguments", ["package='app', resource='weights.bin'", "'app', resource='weights.bin'"]
)
def test_old_keywords_still_work(tmp_path, function, arguments):
    relative = functional_project(tmp_path, function, arguments, "weights.bin")
    assert relative in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("function", ["read_binary", "open_binary", "read_text", "open_text"])
@pytest.mark.parametrize(
    "layout",
    [
        "package",
        "subpackage",
        "module",
        "top",
        "namespace",
        "custom",
        "exact",
        "parent",
        "precedence",
    ],
)
def test_functional_module_anchor_shared_resolution(tmp_path, function, layout):
    resource_project(tmp_path, "", "unused")
    anchor = "app.config"
    directory = tmp_path / "src/app"
    mapping = None
    if layout == "package":
        anchor = "app"
    elif layout in {"subpackage", "precedence"}:
        (directory / "config").mkdir()
        (directory / "config/__init__.py").write_text("")
        if layout == "precedence":
            (directory / "config.py").write_text("")
            (directory / "weights.bin").write_text("WRONG")
        directory /= "config"
    elif layout == "top":
        anchor = "config"
        directory = tmp_path / "src"
    elif layout == "custom":
        directory = tmp_path / "lib/app"
        mapping = "{''='lib'}"
    elif layout in {"exact", "parent"}:
        directory = tmp_path / "code"
        mapping = "{'app.config'='code/config'}" if layout == "exact" else "{'app'='code'}"
    directory.mkdir(parents=True, exist_ok=True)
    if layout not in {"package", "subpackage", "precedence"}:
        (directory / "config.py").write_text("")
    if layout == "namespace":
        (tmp_path / "src/app/__init__.py").unlink()
    path = directory / "weights.bin"
    path.write_text("RESOURCE")
    if mapping:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(pyproject.read_text() + f"[tool.setuptools]\npackage-dir={mapping}\n")
    (directory / "main.py" if layout == "custom" else tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import {function}\n"
        f"def main(): return {function}({anchor!r}, 'weights.bin')\n"
    )
    assessment = assess(tmp_path)
    resource_paths = {item.path for item in assessment.resources}
    assert path.relative_to(tmp_path).as_posix() in resource_paths
    if layout == "precedence":
        assert "src/app/weights.bin" not in resource_paths


@pytest.mark.parametrize("state", ["secret", "dirty", "untracked"])
@pytest.mark.usefixtures("offline_tools")
def test_multipath_release_security_and_provenance(tmp_path, monkeypatch, state):
    root = tmp_path / "source"
    relative = functional_project(
        root,
        "read_text",
        "'app', 'models', 'weights.bin', encoding='utf-8'",
        imports=(
            "from importlib.resources import read_text\nfrom os import getenv\n"
            "PASSWORD=getenv('DB_PASSWORD')"
        ),
    )
    secret = "PDBMultipathConfiguredSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    if state == "secret":
        (root / relative).write_text(secret)
    else:
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
            subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
        if state == "dirty":
            (root / relative).write_text("CHANGED")
        else:
            subprocess.run(
                ["git", "-C", str(root), "rm", "--cached", relative],
                check=True,
                capture_output=True,
            )
    with pytest.raises(PreparationError) as error:
        generate_deployment_kit(
            MaterializedRepository(root=root, source=str(root), source_kind="local"),
            tmp_path / "kit",
        )
    assert secret not in str(error.value)
    assert not (tmp_path / "kit").exists()


@pytest.mark.parametrize("function", ["read_text", "open_text"])
def test_exact_text_templates_multipath_staging(tmp_path, function):
    relative = functional_project(
        tmp_path,
        function,
        "'app', 'templates', 'defaults.txt', encoding='utf-8'",
        "templates/defaults.txt",
    )
    assessment = assess(tmp_path)
    resource = next(item for item in assessment.resources if item.path == relative)
    assert any(f"importlib.resources.{function}()" in e.detail for e in resource.evidence)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("packaged", [False, True])
def test_multipath_respects_package_source_constraints(tmp_path, packaged):
    _write_mode_project(tmp_path, mapped=True, target="installed_app.main:main")
    directory = tmp_path / "code/bundle"
    directory.mkdir()
    (directory / "weights.bin").write_bytes(b"BINARY")
    (tmp_path / "code/main.py").write_text(
        "from importlib.resources import read_binary\n"
        "def main(): return read_binary('installed_app', 'bundle', 'weights.bin')\n"
    )
    if packaged:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            pyproject.read_text()
            + "[tool.setuptools.package-data]\ninstalled_app=['bundle/*.bin']\n"
        )
    assessment = assess(tmp_path)
    resource = next(item for item in assessment.resources if item.path == "code/bundle/weights.bin")
    assert resource.packaging_status == ("packaged" if packaged else "repository_adjacent")
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert plan.deployment_mode_condition == (
        "ENTRYPOINT_REQUIRES_PACKAGE_MODE" if packaged else "DEPLOYMENT_MODE_CONFLICT"
    )
    if not packaged:
        assert not assessment.project.package_data


def test_multipath_resolved_escape_cannot_promote_resource(tmp_path, monkeypatch):
    root = tmp_path / "source"
    relative = functional_project(root)
    escaping = root / relative
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"OUTSIDE")
    original = Path.resolve
    monkeypatch.setattr(
        Path, "resolve", lambda p, *a, **kw: outside if p == escaping else original(p, *a, **kw)
    )
    assessment = assess(root)
    assert not any(
        item.path == relative and item.role.value == "runtime_resource"
        for item in assessment.file_inventory
    )


@pytest.mark.parametrize(
    "arguments",
    [
        "'app', 'model', 'utf-8', 'strict', errors='ignore'",
        "'app', 'model', encoding='utf-8', encoding='ascii'",
        "'app', 'model', 'utf-8', unknown=True",
    ],
)
def test_no_valid_text_family_for_conflicting_arguments(arguments):
    call = ast.parse(f"read_text({arguments})", mode="eval").body
    assert _functional_resource_call(call, "read_text") is None
