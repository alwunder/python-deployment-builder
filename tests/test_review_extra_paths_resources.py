"""PR #9 regressions: approved-edge context, artifact ownership, legacy keywords."""

import ast
import json
from types import SimpleNamespace

import pytest
from packaging.requirements import Requirement
from packaging.version import Version
from test_generation import _make_wheel, _plan, _update_indexed_hashes

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import (
    _approved_package_activated_extras,
    _parent_dependency_extras_proven,
    _parent_dependency_presence_proven,
    validate_approved_requires_dist,
    validate_approved_wheel,
)
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.manifest import build_deployment_manifest
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.generation.structural import (
    approved_artifacts_by_path,
    trusted_artifact_wheel_paths,
)
from python_deployment_builder.models import ApprovedArtifact
from python_deployment_builder.planning.lockfile import inspect_uv_lock
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.validation.static import validate_static_kit


def repo(root):
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def write_source(root, source="def main(): return 0\n", dependencies="[]"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.py").write_text(source, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[project]\nname='review-demo'\nversion='1'\nrequires-python='>=3.12'\n"
        f"dependencies={dependencies}\n[project.scripts]\nreview-demo='main:main'\n"
    )
    (root / "uv.lock").write_text(
        "version=1\nrequires-python='>=3.12'\n[[package]]\n"
        "name='review-demo'\nversion='1'\nsource={virtual='.'}\n"
    )


@pytest.fixture
def fake_preparation(tmp_path, monkeypatch):
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


def extra_plan(root):
    (root / "uv.lock").write_text(
        "version=1\n[[package]]\nname='app'\nsource={virtual='.'}\n"
        "[package.optional-dependencies]\nmap=[{name='pywebview'}]\n"
        "[[package]]\nname='pywebview'\nversion='1'\ndependencies=[{name='proxy-tools'}]\n"
        "[[package]]\nname='proxy-tools'\nversion='0.1.0'\n"
        "sdist={url='https://example.invalid/proxy_tools-0.1.0.tar.gz'}\n"
        "dependencies=[{name='helper'}]\n"
        "[[package]]\nname='helper'\nversion='1'\n"
        "wheels=[{url='https://example.invalid/helper-1-py3-none-any.whl'}]\n"
    )
    plan = _plan().model_copy(deep=True)
    plan.lock_graph = inspect_uv_lock(root, "app", "3.12", "x86_64", ["map"])
    plan.runtime.selected_extras = ["map"]
    return plan


def test_approved_normal_dependency_beneath_root_extra(tmp_path):
    plan = extra_plan(tmp_path)
    graph = plan.lock_graph
    assert _approved_package_activated_extras(graph, plan, "proxy-tools") == set()
    edge = next(item for item in graph.edges if item.from_package == "proxy-tools")
    assert edge.selected_extra == "map"
    assert edge.activated_dependency_extra is None
    assert any(item.name == "helper" for item in graph.dependencies)
    wheel = _make_wheel(tmp_path, requires_dist_values=["helper>=1"])
    assert (
        validate_approved_wheel(f"proxy-tools={wheel}", plan)[0].distribution_name == "proxy-tools"
    )


def two_artifact_kit(tmp_path):
    source = tmp_path / "source"
    write_source(source, dependencies="['foo==1', 'bar==1']")
    with (source / "uv.lock").open("a") as stream:
        stream.write("dependencies=[{name='foo'}, {name='bar'}]\n")
        for name in ["foo", "bar"]:
            stream.write(
                f"[[package]]\nname='{name}'\nversion='1'\n"
                f"sdist={{url='https://example.invalid/{name}-1.tar.gz'}}\n"
            )
    wheels = [_make_wheel(tmp_path, name=name, version="1") for name in ["foo", "bar"]]
    kit = tmp_path / "kit"
    generate_deployment_kit(
        repo(source),
        kit,
        bootstrap_mode="online_cmd",
        artifact_values=[
            f"{name}={wheel}" for name, wheel in zip(["foo", "bar"], wheels, strict=True)
        ],
    )
    assert validate_static_kit(kit).final_state.value == "STATIC_VALID"
    return kit


@pytest.mark.parametrize("case_variant", [False, True])
@pytest.mark.parametrize("version", ["1", "1.0.0"])
def test_duplicate_approved_path_rejected_after_consistent_reindex(
    tmp_path, fake_preparation, case_variant, version
):
    kit = two_artifact_kit(tmp_path)
    manifest_path = kit / "deployment/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    records = {item["distribution_name"]: item for item in manifest["approved_artifacts"]}
    records["foo"]["filename"] = records["bar"]["filename"]
    if case_variant:
        records["foo"]["filename"] = records["foo"]["filename"].upper()
    records["foo"]["version"] = version
    records["foo"]["sha256"] = records["bar"]["sha256"]
    # Preserve both lock identities and suppression pairs, with bar last in the old map.
    manifest["approved_artifacts"] = [records["foo"], records["bar"]]
    removed = "deployment/wheels/foo-1-py3-none-any.whl"
    (kit / removed).unlink()
    manifest["referenced_files"] = [x for x in manifest["referenced_files"] if x != removed]
    manifest_path.write_text(json.dumps(manifest))
    index_path = kit / "deployment/generated-files.json"
    index = json.loads(index_path.read_text())
    index["files"] = [x for x in index["files"] if x["path"] != removed]
    index_path.write_text(json.dumps(index))
    _update_indexed_hashes(kit, "deployment/manifest.json")
    report = validate_static_kit(kit)
    checks = {item.code: item for item in report.static_checks}
    assert checks["APPROVED_ARTIFACT_LOCK_IDENTITY"].status.value == "PASS"
    assert checks["SYNC_ARGUMENTS_CONTRACT"].status.value == "PASS"
    assert checks["GENERATED_FILE_HASHES"].status.value == "PASS"
    assert report.final_state.value == "FAILED", "one physical wheel cannot own foo and bar"
    assert checks["APPROVED_ARTIFACT_PATH_UNIQUENESS"].status.value == "FAIL"
    assert checks["WHEEL_METADATA_SEMANTICS"].status.value == "FAIL"


def test_static_identity_uniqueness_separate_from_path_uniqueness(tmp_path, fake_preparation):
    kit = two_artifact_kit(tmp_path)
    path = kit / "deployment/manifest.json"
    manifest = json.loads(path.read_text())
    manifest["approved_artifacts"][0]["distribution_name"] = manifest["approved_artifacts"][1][
        "distribution_name"
    ]
    manifest["approved_artifacts"][0]["version"] = "1.0.0"
    path.write_text(json.dumps(manifest))
    _update_indexed_hashes(kit, "deployment/manifest.json")
    checks = {item.code: item for item in validate_static_kit(kit).static_checks}
    assert checks["APPROVED_ARTIFACT_PATH_UNIQUENESS"].status.value == "PASS"
    assert checks["APPROVED_ARTIFACT_LOCK_IDENTITY"].status.value == "FAIL"
    assert any("repeats" in item for item in checks["APPROVED_ARTIFACT_LOCK_IDENTITY"].evidence)


@pytest.mark.parametrize("function", ["read_text", "read_binary", "open_text", "open_binary"])
@pytest.mark.parametrize("binding", ["module", "module_alias", "direct", "direct_alias"])
@pytest.mark.parametrize(
    "arguments",
    [
        "'app', 'defaults.json'",
        "'app', resource='defaults.json'",
        "package='app', resource='defaults.json'",
    ],
)
def test_legacy_keyword_resource_staged(tmp_path, function, binding, arguments):
    write_source(tmp_path, "def main(): return 0\n")
    project = tmp_path / "pyproject.toml"
    project.write_text(project.read_text().replace("main:main", "app.main:main"))
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("")
    imports, call = {
        "module": ("import importlib.resources", f"importlib.resources.{function}"),
        "module_alias": ("import importlib.resources as ir", f"ir.{function}"),
        "direct": (f"from importlib.resources import {function}", function),
        "direct_alias": (f"from importlib.resources import {function} as read", "read"),
    }[binding]
    source = f"{imports}\ndef main():\n    return {call}({arguments})\n"
    (tmp_path / "src/app/main.py").write_text(source)
    (tmp_path / "src/app/defaults.json").write_text("{}")
    call = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call))
    if arguments.startswith("package="):
        assert call.args == []
    assessment = assess_repository(repo(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert plan.deployment_mode == "source"
    assert "src/app/defaults.json" in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize(
    ("root_extra", "selected", "parent_extra", "activated", "accepted"),
    [
        (None, [], None, [], True),
        ("map", ["map"], None, [], True),
        ("map", [], None, ["map"], False),
        ("map", ["map"], "map", [], False),
        ("map", ["map"], "feature", ["feature"], True),
        (None, [], "feature", [], False),
        (None, [], "feature", ["feature"], True),
        ("MAP", ["map"], "FEATURE", ["feature"], True),
    ],
)
def test_parent_edge_context_dimensions(
    tmp_path, root_extra, selected, parent_extra, activated, accepted
):
    plan = extra_plan(tmp_path)
    graph = plan.lock_graph
    graph.selected_extras = selected
    edge = next(item for item in graph.edges if item.from_package == "proxy-tools")
    edge.selected_extra = root_extra
    edge.activated_dependency_extra = parent_extra
    edge.requested_dependency_extras = ["child"]
    for proof, args in [
        (
            _parent_dependency_presence_proven,
            (graph, plan, "proxy-tools", "helper", set(activated)),
        ),
        (
            _parent_dependency_extras_proven,
            (Requirement("helper[child]"), graph, plan, "proxy-tools", set(activated)),
        ),
    ]:
        if accepted:
            proof(*args)
        else:
            with pytest.raises(PreparationError):
                proof(*args)


@pytest.mark.parametrize(
    ("marker", "accepted"),
    [
        (None, True),
        ("sys_platform == 'win32'", True),
        ("sys_platform == 'linux'", False),
        ("python_full_version >= '3.12.5'", False),
        ("not a valid marker", False),
    ],
)
def test_parent_edge_strict_marker_proof(tmp_path, marker, accepted):
    plan = extra_plan(tmp_path)
    graph = plan.lock_graph
    edge = next(item for item in graph.edges if item.from_package == "proxy-tools")
    edge.marker = marker
    edge.applicable = True  # This optimistic summary must not replace tri-state proof.
    edge.requested_dependency_extras = ["child"]
    for proof, args in [
        (_parent_dependency_presence_proven, (graph, plan, "proxy-tools", "helper", set())),
        (
            _parent_dependency_extras_proven,
            (Requirement("helper[child]"), graph, plan, "proxy-tools", set()),
        ),
    ]:
        if accepted:
            proof(*args)
        else:
            with pytest.raises(PreparationError):
                proof(*args)


@pytest.mark.parametrize(
    ("selected", "requested", "expected"),
    [
        (["map"], [], set()),
        (["map"], ["feature"], {"feature"}),
        (["map"], ["map"], {"map"}),
        ([], ["feature"], set()),
    ],
)
def test_incoming_extras_are_not_root_extras(tmp_path, selected, requested, expected):
    plan = extra_plan(tmp_path)
    graph = plan.lock_graph
    graph.selected_extras = selected
    incoming = next(item for item in graph.edges if item.to_package == "proxy-tools")
    incoming.requested_dependency_extras = requested
    assert _approved_package_activated_extras(graph, plan, "proxy-tools") == expected


@pytest.mark.parametrize("requested", [[], ["feature"]])
def test_incoming_extra_activates_parent_optional_dependency(tmp_path, requested):
    plan = extra_plan(tmp_path)
    graph = plan.lock_graph
    incoming = next(item for item in graph.edges if item.to_package == "proxy-tools")
    incoming.requested_dependency_extras = requested
    outgoing = next(item for item in graph.edges if item.from_package == "proxy-tools")
    outgoing.activated_dependency_extra = "feature"
    outgoing.requested_dependency_extras = ["child"]
    next(
        item for item in graph.dependencies if item.name == "helper"
    ).available_dependency_extras = ["child"]
    if requested:
        validate_approved_requires_dist(["helper[child]>=1"], plan, "proxy-tools", Version("0.1.0"))
    else:
        with pytest.raises(PreparationError, match="no proxy-tools dependency edge"):
            validate_approved_requires_dist(
                ["helper[child]>=1"], plan, "proxy-tools", Version("0.1.0")
            )


@pytest.mark.parametrize("marker", ["sys_platform == 'linux'", "python_full_version >= '3.12.5'"])
def test_unproven_incoming_edges_do_not_activate_extras(tmp_path, marker):
    plan = extra_plan(tmp_path)
    incoming = next(item for item in plan.lock_graph.edges if item.to_package == "proxy-tools")
    incoming.requested_dependency_extras = ["feature"]
    incoming.marker = marker
    assert _approved_package_activated_extras(plan.lock_graph, plan, "proxy-tools") == set()


@pytest.mark.parametrize(
    ("requirement", "accepted"),
    [
        ("helper>=1", True),
        ("helper>=2", False),
        ("proxy-tools==0.1", True),
        ("proxy-tools>=1", False),
        ("helper @ https://example.invalid/helper.whl", False),
        ("helper>=2; extra == 'map'", True),  # Root map does not activate parent map.
    ],
)
def test_approved_requirement_semantics_after_selection(tmp_path, requirement, accepted):
    plan = extra_plan(tmp_path)
    if accepted:
        validate_approved_requires_dist([requirement], plan, "proxy-tools", Version("0.1.0"))
    else:
        with pytest.raises(PreparationError):
            validate_approved_requires_dist([requirement], plan, "proxy-tools", Version("0.1.0"))


def artifact(name, filename, version="1"):
    return ApprovedArtifact(
        distribution_name=name,
        version=version,
        filename=filename,
        sha256="0" * 64,
        wheel_tags=["py3-none-any"],
    )


@pytest.mark.parametrize(
    "filenames",
    [
        ["foo-1-py3-none-any.whl", "foo-1-py3-none-any.whl"],
        ["Foo-1-py3-none-any.whl", "foo-1-py3-none-any.whl"],
        ["foo-1-py3-none-any.whl", "FOO-1-PY3-NONE-ANY.WHL"],
    ],
)
@pytest.mark.parametrize("version", ["1", "1.0.0"])
def test_approved_materialization_paths_are_windows_unique(tmp_path, filenames, version):
    records = [artifact("foo", filenames[0]), artifact("bar", filenames[1], version)]
    with pytest.raises(PreparationError, match="Duplicate approved artifact materialization path"):
        approved_artifacts_by_path(records)
    # The independently callable generation manifest API enforces the same invariant.
    with pytest.raises(PreparationError, match="Duplicate approved artifact materialization path"):
        build_deployment_manifest(
            _plan(),
            tmp_path,
            bootstrap_mode="online_cmd",
            system_certs=False,
            approved_artifacts=records,
            bundled_uv_sha256=None,
            referenced_files=[],
        )


@pytest.mark.parametrize(
    "filenames",
    [[], ["foo-1-py3-none-any.whl"], ["foo-1-py3-none-any.whl", "bar-1-py3-none-any.whl"]],
)
def test_distinct_approved_paths(filenames):
    records = [artifact(str(index), name) for index, name in enumerate(filenames)]
    assert len(approved_artifacts_by_path(records)) == len(records)


def test_application_and_approved_basename_are_separate_paths():
    record = artifact("foo", "foo-1-py3-none-any.whl")
    assert len(approved_artifacts_by_path([record])) == 1
    manifest = SimpleNamespace(approved_artifacts=[record], application_artifact=record)
    assert trusted_artifact_wheel_paths(manifest) == {
        "deployment/wheels/foo-1-py3-none-any.whl",
        "deployment/application/foo-1-py3-none-any.whl",
    }


@pytest.mark.parametrize(
    "filename", ["../foo.whl", "nested/foo.whl", "nested\\foo.whl", "C:\\foo.whl"]
)
def test_approved_path_safety(filename):
    with pytest.raises(PreparationError, match="Unsafe approved artifact filename"):
        approved_artifacts_by_path([artifact("foo", filename)])


@pytest.mark.parametrize("function", ["read_text", "read_binary", "open_text", "open_binary"])
@pytest.mark.parametrize(
    "arguments",
    [
        "package=dynamic, resource='defaults.json'",
        "package='app', resource=dynamic",
        "package='app', resource='../defaults.json'",
        "package='app', resource='templates/defaults.json'",
        "package='app', resource='defaults.json', unknown=True",
    ],
)
def test_legacy_keyword_resource_safety(tmp_path, function, arguments):
    write_source(
        tmp_path,
        "import importlib.resources\n"
        f"def main(): return importlib.resources.{function}({arguments})\n",
    )
    (tmp_path / "app/templates").mkdir(parents=True)
    (tmp_path / "app/__init__.py").write_text("")
    (tmp_path / "app/defaults.json").write_text("{}")
    (tmp_path / "app/templates/defaults.json").write_text("{}")
    assert all(
        item.kind == "unresolved_path_reference"
        for item in assess_repository(repo(tmp_path)).resources
    )


@pytest.mark.parametrize("function", ["read_binary", "open_binary"])
def test_legacy_binary_encoding_keyword_is_unresolved(tmp_path, function):
    write_source(
        tmp_path,
        f"from importlib.resources import {function}\n"
        f"def main(): return {function}(package='app', "
        "resource='defaults.json', encoding='utf-8')\n",
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app/__init__.py").write_text("")
    (tmp_path / "app/defaults.json").write_text("{}")
    assert all(
        item.kind == "unresolved_path_reference"
        for item in assess_repository(repo(tmp_path)).resources
    )


@pytest.mark.parametrize("function", ["read_text", "read_binary", "open_text", "open_binary"])
def test_unrelated_legacy_resource_function_untouched(tmp_path, function):
    write_source(
        tmp_path,
        f"def {function}(package, resource): return None\n"
        f"def main(): return {function}(package='app', resource='defaults.json')\n",
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app/__init__.py").write_text("")
    (tmp_path / "app/defaults.json").write_text("{}")
    assert not assess_repository(repo(tmp_path)).resources


@pytest.mark.parametrize("function", ["read_text", "open_text"])
def test_legacy_keyword_text_options_and_positional_wins(tmp_path, function):
    write_source(
        tmp_path,
        f"from importlib.resources import {function} as read\n"
        "def main(): return read('app', 'defaults.json', package='wrong', "
        "resource='wrong.json', encoding='utf-8', errors='strict')\n",
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app/__init__.py").write_text("")
    (tmp_path / "app/defaults.json").write_text("{}")
    assert [item.path for item in assess_repository(repo(tmp_path)).resources] == [
        "app/defaults.json"
    ]


@pytest.mark.parametrize("function", ["read_text", "read_binary", "open_text", "open_binary"])
def test_legacy_keyword_resource_security(tmp_path, fake_preparation, monkeypatch, function):
    source = tmp_path / "source"
    write_source(
        source,
        "from os import getenv as read_env\nimport importlib.resources\n"
        "def main():\n    read_env(key='DB_PASSWORD')\n"
        f"    return importlib.resources.{function}(package='app', resource='defaults.json')\n",
    )
    (source / "app").mkdir()
    (source / "app/__init__.py").write_text("")
    secret = "PDBSyntheticSecret123"
    (source / "app/defaults.json").write_text(secret)
    monkeypatch.setenv("DB_PASSWORD", secret)
    with pytest.raises(PreparationError, match="SECRET") as caught:
        generate_deployment_kit(repo(source), tmp_path / "kit", bootstrap_mode="online_cmd")
    assert secret not in str(caught.value)
    assert not (tmp_path / "kit").exists()
