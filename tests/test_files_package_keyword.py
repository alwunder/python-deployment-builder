"""Compatible explicit files(package=...) anchors use the existing resolver."""

import pytest
from test_dependency_authority import assess

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.planning.planner import create_deployment_plan


def resource_project(root, imports, call, source_root="src", mapping=None):
    package = root / source_root / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "defaults.json").write_text("{}\n")
    (package / "main.py").write_text(
        f"{imports}\ndef main():\n return {call}.joinpath('defaults.json').read_text()\n"
    )
    (root / "pyproject.toml").write_text(
        "[project]\nname='demo'\nversion='1.0'\nrequires-python='>=3.12'\n"
        "[project.scripts]\ndemo='app.main:main'\n"
        + (f"[tool.setuptools]\npackages=['app']\npackage-dir={mapping}\n" if mapping else "")
    )
    (root / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
        "[[package]]\nname='demo'\nversion='1.0'\nsource={virtual='.'}\n"
    )
    return (package / "defaults.json").relative_to(root).as_posix()


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("import importlib.resources", "importlib.resources.files(package='app')"),
        ("import importlib.resources as resources", "resources.files(package='app')"),
        ("from importlib import resources", "resources.files(package='app')"),
        ("from importlib import resources as resources", "resources.files(package='app')"),
        ("from importlib.resources import files", "files(package='app')"),
        ("from importlib.resources import files as rf", "rf(package='app')"),
    ],
)
def test_package_keyword_promotes_and_stages_resource(tmp_path, imports, call):
    path = resource_project(tmp_path, imports, call)
    assessment = assess(tmp_path)
    assert any(item.path == path for item in assessment.resources)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert path in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("argument", ["'app'", "anchor='app'", "package='app'", ""])
@pytest.mark.parametrize(
    ("source_root", "mapping"),
    [
        (".", None),
        ("src", None),
        ("lib", "{''='lib'}"),
        ("lib", "{'app'='lib/app'}"),
    ],
)
def test_files_anchor_forms_share_source_root_resolution(tmp_path, argument, source_root, mapping):
    path = resource_project(
        tmp_path,
        "from importlib.resources import files",
        f"files({argument})",
        source_root,
        mapping,
    )
    assessment = assess(tmp_path)
    assert any(item.path == path for item in assessment.resources)


@pytest.mark.parametrize(
    "argument",
    [
        "anchor='app', package='other'",
        "foo='app'",
        "package=unknown",
        "**{'package':'app'}",
        "'app', 'other'",
        "package='../app'",
        "package='/app'",
        "package='app', foo='ignored'",
    ],
)
def test_unknown_or_conflicting_files_anchor_is_unresolved(tmp_path, argument):
    path = resource_project(tmp_path, "from importlib.resources import files", f"files({argument})")
    assert all(item.path != path for item in assess(tmp_path).resources)


@pytest.mark.parametrize("argument", ["'app', package='other'", "'app', anchor='other'"])
def test_files_positional_argument_wins_duplicate_binding(tmp_path, argument):
    path = resource_project(tmp_path, "from importlib.resources import files", f"files({argument})")
    assert any(item.path == path for item in assess(tmp_path).resources)


def test_files_package_keyword_uses_static_assignment_resolver(tmp_path):
    path = resource_project(
        tmp_path, "from importlib.resources import files\nPACKAGE='app'", "files(package=PACKAGE)"
    )
    assert any(item.path == path for item in assess(tmp_path).resources)


def test_user_defined_files_is_not_promoted(tmp_path):
    path = resource_project(tmp_path, "def files(**kwargs): return None", "files(package='app')")
    assert all(item.path != path for item in assess(tmp_path).resources)


def test_files_package_keyword_parent_mapping(tmp_path):
    path = resource_project(
        tmp_path,
        "from importlib.resources import files",
        "files(package='app')",
        "lib",
        "{'app'='lib/app'}",
    )
    parent = tmp_path / "lib/app"
    child = parent / "child"
    child.mkdir()
    (child / "__init__.py").write_text("")
    (child / "defaults.json").write_text("{}")
    (parent / "main.py").write_text(
        "from importlib.resources import files\n"
        "def main(): return files(package='app.child').joinpath('defaults.json').read_text()\n"
    )
    resources = {item.path for item in assess(tmp_path).resources}
    assert "lib/app/child/defaults.json" in resources
    assert path not in resources


def test_files_package_keyword_rejects_joinpath_traversal(tmp_path):
    path = resource_project(
        tmp_path, "from importlib.resources import files", "files(package='app')"
    )
    main = tmp_path / "src/app/main.py"
    main.write_text(main.read_text().replace("'defaults.json'", "'../app/defaults.json'"))
    assert all(item.path != path for item in assess(tmp_path).resources)


def test_keyword_promoted_resource_receives_release_security_scan(tmp_path, monkeypatch):
    source = tmp_path / "source"
    path = resource_project(source, "from importlib.resources import files", "files(package='app')")
    (source / path).write_text("API_KEY = 'sk-abcdefghijklmnop'\n")
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
    with pytest.raises(PreparationError, match="NO_SECRET_VALUES"):
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            tmp_path / "kit",
        )
    assert not (tmp_path / "kit").exists()
