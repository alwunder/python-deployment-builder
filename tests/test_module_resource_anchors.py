"""Explicit module anchors select the module's containing resource directory."""

from pathlib import Path

import pytest
from test_dependency_authority import assess
from test_files_package_keyword import resource_project

from python_deployment_builder.analysis.inventory import _module_files
from python_deployment_builder.analysis.module_resolution import module_resource_roots
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.planning.planner import create_deployment_plan


@pytest.mark.parametrize(
    "argument", ["'app.config'", "anchor='app.config'", "package='app.config'"]
)
def test_literal_module_anchor_promotes_resource(tmp_path, argument):
    path = resource_project(tmp_path, "from importlib.resources import files", f"files({argument})")
    (tmp_path / "src/app/config.py").write_text("VALUE=1\n")
    assessment = assess(tmp_path)
    assert any(item.path == path for item in assessment.resources)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert path in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize(
    ("imports", "function"),
    [
        ("import importlib.resources", "importlib.resources.files"),
        ("import importlib.resources as resources", "resources.files"),
        ("from importlib import resources as r", "r.files"),
        ("from importlib.resources import files", "files"),
        ("from importlib.resources import files as rf", "rf"),
    ],
)
@pytest.mark.parametrize("keyword", ["", "anchor=", "package="])
def test_module_anchor_bindings(tmp_path, imports, function, keyword):
    path = resource_project(tmp_path, imports, f"{function}({keyword}'app.config')")
    (tmp_path / "src/app/config.py").write_text("")
    assert path in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize(
    ("source_root", "mapping"),
    [(".", None), ("src", None), ("lib", "{''='lib'}"), ("lib", "{'app'='lib/app'}")],
)
@pytest.mark.parametrize("namespace", [False, True])
def test_module_anchor_source_roots_and_namespace_parent(tmp_path, source_root, mapping, namespace):
    path = resource_project(
        tmp_path,
        "from importlib.resources import files",
        "files('app.config')",
        source_root,
        mapping,
    )
    package = tmp_path / source_root / "app"
    (package / "config.py").write_text("")
    if namespace:
        (package / "__init__.py").unlink()
    assessment = assess(tmp_path)
    assert path in {item.path for item in assessment.resources}
    assert (package / "__init__.py").exists() != namespace
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    if mapping == "{'app'='lib/app'}":
        # Exact package-dir relocation is installed-only under the existing
        # planner. Resource discovery must not invent a source-mode override.
        assert plan.deployment_mode == "package"
        assert plan.deployment_mode_condition == "DEPLOYMENT_MODE_CONFLICT"
        # The non-wheel-backed adjacent resource creates the established
        # installed-only/source-resource conflict, not an omitted resource.
    else:
        assert plan.deployment_mode == "source"
        assert path in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("module", ["app", "app.child", "app.config", "config"])
def test_package_subpackage_module_and_top_level_anchors(tmp_path, module):
    resource_project(tmp_path, "from importlib.resources import files", f"files('{module}')")
    (tmp_path / "src/app/config.py").write_text("")
    (tmp_path / "src/config.py").write_text("")
    (tmp_path / "src/defaults.json").write_text("{}")
    child = tmp_path / "src/app/child"
    child.mkdir()
    (child / "__init__.py").write_text("")
    (child / "defaults.json").write_text("{}")
    expected = {
        "app": "src/app/defaults.json",
        "app.child": "src/app/child/defaults.json",
        "app.config": "src/app/defaults.json",
        "config": "src/defaults.json",
    }[module]
    assert {item.path for item in assess(tmp_path).resources} == {expected}


@pytest.mark.parametrize(
    ("mappings", "module", "location"),
    [
        ({"app": "lib"}, "app.config", "lib/config"),
        ({"app": "lib", "app.child": "code"}, "app.child.config", "code/config"),
        ({"app.child": "code"}, "app.child", "code"),
    ],
)
def test_inventory_and_resource_anchors_share_mapping_locations(
    tmp_path, mappings, module, location
):
    module_file = (tmp_path / location).with_suffix(".py")
    module_file.parent.mkdir(parents=True, exist_ok=True)
    module_file.write_text("")
    assert module_file in _module_files(tmp_path, module, ["."], mappings)
    assert module_resource_roots(tmp_path, module, ["."], mappings) == [module_file.parent]


def test_longest_parent_mapping_promotes_resource(tmp_path):
    resource_project(
        tmp_path,
        "from importlib.resources import files",
        "files('app.child.config')",
        "lib",
        "{'app'='lib/app', 'app.child'='code'}",
    )
    child = tmp_path / "code"
    child.mkdir()
    (child / "__init__.py").write_text("")
    (child / "config.py").write_text("")
    (child / "defaults.json").write_text("{}")
    assert {item.path for item in assess(tmp_path).resources} == {"code/defaults.json"}


def test_regular_package_wins_same_named_module(tmp_path):
    path = resource_project(
        tmp_path, "from importlib.resources import files", "files('app.config')"
    )
    (tmp_path / "src/app/config.py").write_text("")
    package = tmp_path / "src/app/config"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "defaults.json").write_text("{}")
    resources = {item.path for item in assess(tmp_path).resources}
    assert "src/app/config/defaults.json" in resources
    assert path not in resources


def test_concrete_module_wins_namespace_directory(tmp_path):
    resource_project(tmp_path, "from importlib.resources import files", "files('app.config')")
    (tmp_path / "src/app/config.py").write_text("")
    namespace = tmp_path / "src/app/config"
    namespace.mkdir()
    (namespace / "defaults.json").write_text("{}")
    assert {item.path for item in assess(tmp_path).resources} == {"src/app/defaults.json"}


@pytest.mark.parametrize(
    "anchor",
    ["unknown", "f'app.{unknown}'", "'app.missing'", "'../app.config'", "'app/config'"],
)
def test_unresolved_or_invalid_module_anchor(tmp_path, anchor):
    path = resource_project(tmp_path, "from importlib.resources import files", f"files({anchor})")
    (tmp_path / "src/app/config.py").write_text("")
    assert path not in {item.path for item in assess(tmp_path).resources}


def test_static_assignment_module_anchor(tmp_path):
    path = resource_project(
        tmp_path, "from importlib.resources import files\nANCHOR='app.config'", "files(ANCHOR)"
    )
    (tmp_path / "src/app/config.py").write_text("")
    assert path in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize(
    ("imports", "anchor"),
    [("import app.config", "app.config"), ("import app.config as config", "config")],
)
def test_module_object_anchor_remains_outside_bounded_value_model(tmp_path, imports, anchor):
    path = resource_project(
        tmp_path, f"from importlib.resources import files\n{imports}", f"files({anchor})"
    )
    (tmp_path / "src/app/config.py").write_text("")
    assert path not in {item.path for item in assess(tmp_path).resources}


def test_module_anchor_rejects_external_source_root_and_mapping(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "config.py").write_text("")
    assert module_resource_roots(root, "config", ["../outside"]) == []
    assert module_resource_roots(root, "app.config", ["."], {"app": "../outside"}) == []


def test_module_anchor_rejects_symlink_escape(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("")
    try:
        (root / "config.py").symlink_to(outside)
    except OSError:
        pytest.skip("Host cannot create symlinks")
    assert module_resource_roots(root, "config", ["."]) == []


@pytest.mark.parametrize("leaf", ["__init__.py", "module.py"])
def test_unsafe_concrete_anchor_cannot_fall_back_to_namespace(tmp_path, monkeypatch, leaf):
    package = tmp_path / "module"
    package.mkdir()
    unsafe = package / leaf if leaf == "__init__.py" else tmp_path / leaf
    unsafe.write_text("")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == unsafe or original(path))
    assert module_resource_roots(tmp_path, "module", ["."]) == []


@pytest.mark.parametrize("configured", [False, True])
def test_module_adjacent_resource_receives_release_security_scanning(
    tmp_path, monkeypatch, configured
):
    source = tmp_path / "source"
    imports = "from importlib.resources import files"
    if configured:
        imports += "\nfrom os import getenv\nPASSWORD=getenv(key='DB_PASSWORD')"
    path = resource_project(source, imports, "files('app.config')")
    (source / "src/app/config.py").write_text("")
    secret = "PDBModuleConfiguredSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    (source / path).write_text(secret if configured else "API_KEY = 'sk-abcdefghijklmnop'\n")
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
    with pytest.raises(PreparationError, match="NO_SECRET_VALUES") as error:
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            tmp_path / "kit",
        )
    assert secret not in str(error.value)
    assert not (tmp_path / "kit").exists()
