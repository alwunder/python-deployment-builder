"""Resource wrappers and literal relative dynamic imports reach existing resolvers."""

import ast
import subprocess

import pytest
from test_dependency_authority import assess
from test_files_package_keyword import resource_project

from python_deployment_builder.analysis.inventory import (
    _imported_modules,
    _literal_dynamic_module_name,
)
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import _importlib_resource_path_values, _path_uses
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.planning.planner import create_deployment_plan


def as_file_project(
    root,
    imports="from importlib.resources import as_file, files",
    call="as_file(files('app') / 'model.dat')",
    source_root="src",
    mapping=None,
):
    resource_project(root, imports, "files('app')", source_root, mapping)
    package = root / source_root / "app"
    (package / "main.py").write_text(
        f"{imports}\ndef main():\n with {call} as path:\n  return path.read_bytes()\n"
    )
    (package / "model.dat").write_bytes(b"model fixture")
    return (package / "model.dat").relative_to(root).as_posix()


def relative_project(
    root,
    call="importlib.import_module('.examples.plugin', package='app')",
    imports="import importlib",
    scope="examples",
    source_root="src",
    mapping=None,
):
    resource_project(root, imports, "unused", source_root, mapping)
    package = root / source_root / "app"
    (package / "main.py").write_text(f"{imports}\ndef main(): return {call}.run()\n")
    target = package / scope
    target.mkdir()
    (target / "__init__.py").write_text("")
    (target / "plugin.py").write_text("def run(): return 42\n")
    return (target / "plugin.py").relative_to(root).as_posix()


def test_as_file_dispatches_already_resolvable_traversable(tmp_path):
    relative = as_file_project(tmp_path)
    source = tmp_path / "src/app/main.py"
    outer = next(
        n
        for n in ast.walk(ast.parse(source.read_text()))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "as_file"
    )
    assert _path_uses(outer) == []
    assert _importlib_resource_path_values(
        outer.args[0],
        root=tmp_path,
        source_path=source,
        source_roots=["src"],
        project=None,
        assignments={},
        returns={},
        module_bindings=set(),
        files_bindings={"files"},
    ) == [relative]
    assessment = assess(tmp_path)
    assert relative in {resource.path for resource in assessment.resources}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize(
    ("imports", "function"),
    [
        ("from importlib.resources import as_file, files", "as_file"),
        (
            "import importlib.resources\nfrom importlib.resources import files",
            "importlib.resources.as_file",
        ),
        (
            "import importlib.resources as resources\nfrom importlib.resources import files",
            "resources.as_file",
        ),
        ("from importlib.resources import as_file as materialize, files", "materialize"),
        (
            "from importlib import resources as r\nfrom importlib.resources import files",
            "r.as_file",
        ),
    ],
)
@pytest.mark.parametrize(
    "expression", ["files('app') / 'model.dat'", "files('app').joinpath('model.dat')"]
)
def test_as_file_binding_and_traversable_matrix(tmp_path, imports, function, expression):
    relative = as_file_project(tmp_path, imports, f"{function}({expression})")
    assessment = assess(tmp_path)
    resource = next(item for item in assessment.resources if item.path == relative)
    assert resource.access_mode == "read"
    assert any("as_file()" in evidence.detail for evidence in resource.evidence)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("anchor", ["'app'", "anchor='app'", "package='app'", "'app.config'"])
@pytest.mark.parametrize(
    ("source_root", "mapping"),
    [("src", None), ("lib", "{''='lib'}"), ("lib", "{'app'='lib/app'}")],
)
def test_as_file_preserves_anchor_and_source_mapping(tmp_path, anchor, source_root, mapping):
    relative = as_file_project(
        tmp_path,
        call=f"as_file(files({anchor}) / 'model.dat')",
        source_root=source_root,
        mapping=mapping,
    )
    (tmp_path / source_root / "app/config.py").write_text("")
    assert relative in {item.path for item in assess(tmp_path).resources}


def test_as_file_longest_parent_mapping(tmp_path):
    as_file_project(
        tmp_path,
        call="as_file(files('app.child.config') / 'model.dat')",
        source_root="lib",
        mapping="{'app'='lib/app','app.child'='code'}",
    )
    child = tmp_path / "code"
    child.mkdir()
    (child / "__init__.py").write_text("")
    (child / "config.py").write_text("")
    (child / "model.dat").write_text("model")
    assert {item.path for item in assess(tmp_path).resources} == {"code/model.dat"}


@pytest.mark.parametrize(
    "call",
    [
        "as_file(unknown)",
        "as_file(files(unknown) / 'model.dat')",
        "as_file(files('app') / unknown)",
        "as_file()",
        "as_file(traversable=files('app') / 'model.dat')",
        "as_file(files('app') / 'model.dat', foo=True)",
        "as_file(files('app') / '../model.dat')",
    ],
)
def test_as_file_invalid_and_dynamic_inputs_are_unresolved(tmp_path, call):
    relative = as_file_project(tmp_path, call=call)
    assert relative not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("body", ["pass", "third_party(path)"])
def test_as_file_read_evidence_requires_no_later_path_use(tmp_path, body):
    relative = as_file_project(tmp_path)
    main = tmp_path / "src/app/main.py"
    main.write_text(main.read_text().replace("return path.read_bytes()", body))
    resource = next(item for item in assess(tmp_path).resources if item.path == relative)
    assert resource.access_mode == "read"


@pytest.mark.parametrize(
    "mapping", ["{'app.examples'='code/docs'}", "{'app'='lib/app','app.examples'='code/docs'}"]
)
def test_relative_import_exact_longest_mapping(tmp_path, mapping):
    relative_project(tmp_path, source_root="lib", mapping=mapping)
    target = tmp_path / "code/docs"
    target.mkdir(parents=True)
    (target / "__init__.py").write_text("")
    (target / "plugin.py").write_text("def run(): return 42\n")
    roles = {item.path: item.role.value for item in assess(tmp_path).file_inventory}
    assert roles["code/docs/plugin.py"] == "application_source"
    assert roles["code/docs/__init__.py"] == "application_source"


def test_unrelated_as_file_does_not_promote_resource(tmp_path):
    relative = as_file_project(
        tmp_path, "from importlib.resources import files\ndef as_file(value): return value"
    )
    assert relative not in {item.path for item in assess(tmp_path).resources}


def test_as_file_directory_promotes_descendants_without_yield_dataflow(tmp_path):
    as_file_project(tmp_path, call="as_file(files('app') / 'bundle')")
    main = tmp_path / "src/app/main.py"
    main.write_text(
        main.read_text().replace("return path.read_bytes()", "return third_party(path)")
    )
    nested = tmp_path / "src/app/bundle/nested/model.dat"
    nested.parent.mkdir(parents=True)
    nested.write_text("model")
    assessment = assess(tmp_path)
    assert "src/app/bundle" in {item.path for item in assessment.resources}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "src/app/bundle/nested/model.dat" in _staging_files(
        tmp_path, assessment, plan, include=True
    )


@pytest.mark.parametrize(
    ("imports", "function"),
    [
        ("import importlib", "importlib.import_module"),
        ("import importlib as il", "il.import_module"),
        ("from importlib import import_module", "import_module"),
        ("from importlib import import_module as load", "load"),
    ],
)
@pytest.mark.parametrize(
    "arguments",
    [
        "'.examples.plugin', 'app'",
        "'.examples.plugin', package='app'",
        "name='.examples.plugin', package='app'",
    ],
)
def test_relative_dynamic_aliases_and_argument_forms(tmp_path, imports, function, arguments):
    relative = relative_project(tmp_path, f"{function}({arguments})", imports)
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    staged = _staging_files(tmp_path, assessment, plan, include=True)
    assert relative in staged
    assert "src/app/examples/__init__.py" in staged
    assert "src/app/__init__.py" in staged


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ("'.plugin', package='app'", "app.plugin"),
        ("'..plugin', package='app.sub'", "app.plugin"),
        ("'.', package='app'", "app"),
        ("'app.plugin', package='other'", "app.plugin"),
        ("'app.plugin', package=unknown", "app.plugin"),
        ("'.plugin', 'app', package='other'", "app.plugin"),
        ("'.plugin', 'app', name='other'", "app.plugin"),
        ("'...plugin', package='app.sub'", None),
        ("'.plugin'", None),
        ("name=unknown, package='app'", None),
        ("'.plugin', package=unknown", None),
        ("f'app.{unknown}', package='app'", None),
        ("'.bad-name', package='app'", None),
        ("'.plugin', package='app..sub'", None),
        ("'.plugin', package=__package__", None),
    ],
)
def test_literal_relative_resolution_rules(arguments, expected):
    node = ast.parse(f"import_module({arguments})", mode="eval").body
    assert _literal_dynamic_module_name(node, builtin=False) == expected


@pytest.mark.parametrize("scope", ["examples", "docs", "tests"])
@pytest.mark.parametrize("namespace", [False, True])
def test_relative_import_promotes_excluded_scope_and_preserves_namespace(
    tmp_path, scope, namespace
):
    relative = relative_project(
        tmp_path, f"importlib.import_module('.{scope}.plugin', 'app')", scope=scope
    )
    if namespace:
        (tmp_path / "src/app/__init__.py").unlink()
        (tmp_path / "src/app" / scope / "__init__.py").unlink()
    assessment = assess(tmp_path)
    roles = {item.path: item.role.value for item in assessment.file_inventory}
    assert roles[relative] == "application_source"
    assert (tmp_path / "src/app/__init__.py").exists() != namespace


@pytest.mark.parametrize("mapping", ["{''='lib'}", "{'app'='lib/app'}"])
def test_relative_import_custom_and_parent_mapping(tmp_path, mapping):
    relative = relative_project(tmp_path, source_root="lib", mapping=mapping)
    assessment = assess(tmp_path)
    assert next(item for item in assessment.file_inventory if item.path == relative).role.value == (
        "application_source"
    )
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    if mapping == "{''='lib'}":
        assert plan.deployment_mode == "source"
        assert relative in _staging_files(tmp_path, assessment, plan, include=True)
    else:
        assert plan.deployment_mode == "package"


@pytest.mark.parametrize(
    "arguments",
    ["'app.examples.plugin'", "name='app.examples.plugin'", "'app.examples.plugin', level=0"],
)
def test_absolute_builtin_import_unchanged(tmp_path, arguments):
    relative = relative_project(tmp_path, f"__import__({arguments})", imports="")
    assert next(
        item for item in assess(tmp_path).file_inventory if item.path == relative
    ).role.value == ("application_source")


@pytest.mark.parametrize(
    "arguments",
    [
        "'.examples.plugin', package='app'",
        "'app.examples.plugin', level=1",
        "'app.examples.plugin', level=unknown",
        "'app.examples.plugin', None, None, (), 1",
    ],
)
def test_builtin_relative_context_is_not_misread_as_absolute(tmp_path, arguments):
    tree = ast.parse(f"__import__({arguments})")
    assert _imported_modules(tree, tmp_path / "main.py", tmp_path, ["."]) == []


def test_unrelated_import_module_is_not_proven(tmp_path):
    relative = relative_project(
        tmp_path,
        "import_module('.examples.plugin', 'app')",
        "def import_module(*args): return None",
    )
    assert next(
        item for item in assess(tmp_path).file_inventory if item.path == relative
    ).role.value == ("example_or_snippet")


@pytest.fixture
def offline_tools(tmp_path, monkeypatch):
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


@pytest.mark.parametrize("configured", [False, True])
def test_as_file_release_security(tmp_path, monkeypatch, offline_tools, configured):
    source = tmp_path / "source"
    imports = "from importlib.resources import as_file, files"
    if configured:
        imports += "\nfrom os import getenv\nPASSWORD=getenv('DB_PASSWORD')"
    as_file_project(source, imports, "as_file(files('app') / 'model.txt')")
    secret = "PDBWrapperConfiguredSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    (source / "src/app/model.txt").write_text(
        secret if configured else "API_KEY='sk-abcdefghijklmnop'"
    )
    with pytest.raises(PreparationError, match="NO_SECRET_VALUES") as error:
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            tmp_path / "kit",
        )
    assert secret not in str(error.value)
    assert not (tmp_path / "kit").exists()


@pytest.mark.parametrize("state", ["dirty", "untracked"])
def test_as_file_git_provenance_is_enforced(tmp_path, offline_tools, state):
    source = tmp_path / "source"
    relative = as_file_project(source)

    def git(*args):
        subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)

    git("init")
    git("add", ".")
    if state == "untracked":
        git("rm", "--cached", relative)
    git(
        "-c",
        "user.name=PDB Test",
        "-c",
        "user.email=pdb@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    if state == "dirty":
        (source / relative).write_bytes(b"changed model")
    with pytest.raises(PreparationError):
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            tmp_path / "kit",
        )
    assert not (tmp_path / "kit").exists()


def test_relative_dynamic_import_promotes_excluded_target(tmp_path):
    relative = relative_project(tmp_path)
    assessment = assess(tmp_path)
    roles = {item.path: item.role.value for item in assessment.file_inventory}
    assert roles[relative] == "application_source"
    assert roles["src/app/examples/__init__.py"] == "application_source"
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)
