"""First-party executable authority and bounded assigned Traversable regressions."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_as_file_relative_imports import as_file_project
from test_dependency_authority import assess
from test_generation import (
    _make_application_wheel,
    _refresh_manifest_wheel_hash,
    _rewrite_application_wheel,
    _update_indexed_hashes,
    _write_mapped_project,
)
from test_review_extra_paths_resources import fake_preparation, repo  # noqa: F401

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import (
    validate_application_wheel,
    validate_application_wheel_surface,
)
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.generation.manifest import build_deployment_manifest
from python_deployment_builder.models import ApplicationArtifact, DeploymentManifest
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.validation.static import validate_static_kit


@pytest.mark.parametrize(
    "extra",
    [
        "requests/__init__.py",
        "application-hook.pth",
        "mapped_app-1.2.3.data/purelib/application-hook.pth",
        "requests/api.py",
        "foreign.py",
        "docs/runtime.py",
        "foreign.PY",
        "HOOK.PTH",
        "sitecustomize.py",
        "usercustomize.py",
        "sitecustomize/__init__.py",
        "usercustomize/__init__.py",
        "mapped_app-1.2.3.data/purelib/foreign.py",
    ],
)
def test_undeclared_executable_wheel_rejected(tmp_path, extra):
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess(source)
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path)
    validate_application_wheel(wheel, assessment, plan)
    _rewrite_application_wheel(wheel, additions={extra: "# benign fixture\n"})
    with pytest.raises(PreparationError, match="authoritative|startup-active"):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    "consumer",
    [
        "with as_file(asset) as path:\n  return path.read_bytes()",
        "return asset.read_bytes()",
        "return asset.read_text()",
    ],
)
def test_assigned_traversable_is_staged(tmp_path, consumer):
    relative = as_file_project(tmp_path)
    (tmp_path / "src/app/main.py").write_text(
        "from importlib.resources import files, as_file\n"
        "asset = files('app') / 'model.dat'\n"
        f"def main():\n {consumer}\n"
    )
    assessment = assess(tmp_path)
    assert relative in {item.path for item in assessment.resources}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert relative in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("missing", ["installed_app/main.py", "installed_app/view.html"])
def test_surface_missing_member_generation_and_independent_validation(tmp_path, missing):
    _write_mapped_project(tmp_path)
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    wheel = _make_application_wheel(tmp_path)
    artifact, _ = validate_application_wheel(wheel, assessment, plan)
    assert artifact.authoritative_members == [
        "installed_app/__init__.py",
        "installed_app/main.py",
        "installed_app/view.html",
    ]
    _rewrite_application_wheel(wheel, removals={missing})
    with pytest.raises(PreparationError, match="missing|entry-point module"):
        validate_application_wheel(wheel, assessment, plan)
    with pytest.raises(PreparationError, match="missing authoritative"):
        validate_application_wheel_surface(
            wheel, artifact.authoritative_members, "installed_app.main"
        )


@pytest.mark.parametrize(
    "extra",
    [
        "installed_app/data/example.pth",
        "installed_app/extra.txt",
        "mapped_app-1.2.3.dist-info/example.py",
    ],
)
def test_benign_non_executable_data_and_metadata_allowed(tmp_path, extra):
    _write_mapped_project(tmp_path)
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    wheel = _make_application_wheel(tmp_path)
    _rewrite_application_wheel(wheel, additions={extra: "# inert fixture\n"})
    artifact, _ = validate_application_wheel(wheel, assessment, plan)
    assert extra not in artifact.authoritative_members  # Never bless observed wheel inventory.
    validate_application_wheel_surface(wheel, artifact.authoritative_members, "installed_app.main")


def test_modeled_second_package_and_module_are_authoritative(tmp_path):
    _write_mapped_project(tmp_path)
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().replace(
            'packages = ["installed_app"]',
            'packages = ["installed_app", "plugins"]\npy-modules = ["helper"]',
        )
    )
    (tmp_path / "plugins").mkdir()
    (tmp_path / "plugins/__init__.py").write_text("")
    (tmp_path / "helper.py").write_text("")
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    wheel = _make_application_wheel(tmp_path)
    _rewrite_application_wheel(wheel, additions={"plugins/__init__.py": "", "helper.py": ""})
    artifact, _ = validate_application_wheel(wheel, assessment, plan)
    assert {"plugins/__init__.py", "helper.py"} <= set(artifact.authoritative_members)


@pytest.mark.parametrize(
    "startup",
    [
        "sitecustomize.py",
        "usercustomize.py",
        "hook.pth",
        "sitecustomize/__init__.py",
        "usercustomize/__init__.py",
    ],
)
def test_declared_startup_destination_still_forbidden(tmp_path, startup):
    wheel = _make_application_wheel(tmp_path)
    _rewrite_application_wheel(wheel, additions={startup: "# startup\n"})
    with pytest.raises(PreparationError, match="startup-active"):
        validate_application_wheel_surface(
            wheel, ["installed_app/main.py", startup], "installed_app.main"
        )


def test_entrypoint_cannot_be_blessed_by_package_data_or_wheel(tmp_path):
    _write_mapped_project(tmp_path)
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    # The supplied wheel contains main.py, but source assessment cannot model it.
    (tmp_path / "code/main.py").unlink()
    with pytest.raises(PreparationError, match="outside the authoritative Python surface"):
        validate_application_wheel(_make_application_wheel(tmp_path), assessment, plan)


@pytest.mark.usefixtures("fake_preparation")
@pytest.mark.parametrize(
    "mutation",
    [
        "requests/__init__.py",
        "hook.pth",
        "mapped_app-1.2.3.data/purelib/hook.pth",
        "sitecustomize.py",
        "usercustomize.py",
        "missing_python",
        "missing_data",
    ],
)
def test_reindexed_static_kit_enforces_source_surface(tmp_path, mutation):
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    wheel = _make_application_wheel(tmp_path)
    kit = tmp_path / "kit"
    generate_deployment_kit(repo(source), kit, application_wheel=wheel, bootstrap_mode="online_cmd")
    assert validate_static_kit(kit).final_state.value == "STATIC_VALID"
    relative = f"deployment/application/{wheel.name}"
    wheel = kit / relative
    if mutation.startswith("missing"):
        missing = (
            "installed_app/main.py" if mutation == "missing_python" else "installed_app/view.html"
        )
        _rewrite_application_wheel(wheel, removals={missing})
    else:
        _rewrite_application_wheel(wheel, additions={mutation: "# fixture\n"})
    _refresh_manifest_wheel_hash(kit, relative)
    manifest_path = kit / "deployment/manifest.json"
    manifest = DeploymentManifest.model_validate_json(manifest_path.read_text())
    plan = create_deployment_plan(assess(source), repository_root=source)
    rebuilt = build_deployment_manifest(
        plan,
        source,
        bootstrap_mode=manifest.bootstrap_mode,
        system_certs=manifest.system_certs,
        approved_artifacts=manifest.approved_artifacts,
        bundled_uv_sha256=manifest.bundled_uv_sha256,
        referenced_files=manifest.referenced_files,
        application_artifact=manifest.application_artifact,
        generated_at=manifest.generated_at,
    )
    manifest.deployment_fingerprint = rebuilt.deployment_fingerprint
    manifest.generation_id = rebuilt.generation_id
    manifest_path.write_text(manifest.model_dump_json(indent=2))
    _update_indexed_hashes(kit, "deployment/manifest.json")
    report = validate_static_kit(kit)
    checks = {item.code: item for item in report.static_checks}
    assert checks["GENERATED_FILE_HASHES"].status.value == "PASS"
    assert checks["WHEEL_METADATA_SEMANTICS"].status.value == "PASS"
    assert checks["APPLICATION_WHEEL_AUTHORITATIVE_SURFACE"].status.value == "FAIL"
    assert report.final_state.value == "FAILED"


def test_surface_required_and_fingerprinted(tmp_path):
    _write_mapped_project(tmp_path)
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    artifact, _ = validate_application_wheel(_make_application_wheel(tmp_path), assessment, plan)
    arguments = dict(
        bootstrap_mode="online_cmd",
        system_certs=False,
        approved_artifacts=[],
        bundled_uv_sha256=None,
        referenced_files=[],
    )
    first = build_deployment_manifest(plan, tmp_path, application_artifact=artifact, **arguments)
    changed = artifact.model_copy(
        update={"authoritative_members": [*artifact.authoritative_members, "new.txt"]}
    )
    second = build_deployment_manifest(plan, tmp_path, application_artifact=changed, **arguments)
    assert first.deployment_fingerprint != second.deployment_fingerprint
    data = artifact.model_dump()
    del data["authoritative_members"]
    with pytest.raises(ValidationError):
        ApplicationArtifact.model_validate(data)
    data["authoritative_members"] = []
    with pytest.raises(ValidationError):
        ApplicationArtifact.model_validate(data)


@pytest.mark.parametrize(
    "assignments",
    [
        "asset = files('app') / 'model.dat'",
        "base = files('app')\nasset = base / 'model.dat'",
        "base = files('app')\nasset = base.joinpath('model.dat')",
        "base = files('app') / 'model.dat'\nother = base\nasset = other",
        "holder.asset = files('app') / 'model.dat'\nasset = holder.asset",
        "def resource():\n return files('app') / 'model.dat'\nasset = resource()",
    ],
)
@pytest.mark.parametrize("consumer", ["asset.read_bytes()", "asset.read_text()", "as_file(asset)"])
def test_bounded_assignment_forms(tmp_path, assignments, consumer):
    relative = as_file_project(tmp_path)
    (tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import files, as_file\n{assignments}\n"
        f"def main(): return {consumer}\n"
    )
    assert relative in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize(
    "assignments",
    [
        "asset = other\nother = asset",
        "asset = asset / 'model.dat'",
        "asset = files(unknown) / 'model.dat'",
        "asset = files('app') / unknown",
        "def resource():\n return resource()\nasset = resource()",
        "def resource():\n return asset\nasset = resource()",
    ],
)
def test_assigned_cycles_and_unknowns_unresolved(tmp_path, assignments):
    relative = as_file_project(tmp_path)
    (tmp_path / "src/app/main.py").write_text(
        f"from importlib.resources import files\n{assignments}\n"
        "def main(): return asset.read_bytes()\n"
    )
    assert relative not in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("anchor", ["'app'", "'app.config'", "anchor='app'", "package='app'", ""])
@pytest.mark.parametrize(
    "source_root,mapping",
    [
        ("src", None),
        ("lib", "{''='lib'}"),
        ("lib", "{'app'='lib/app'}"),
    ],
)
def test_assigned_anchors_and_mappings(tmp_path, anchor, source_root, mapping):
    relative = as_file_project(tmp_path, source_root=source_root, mapping=mapping)
    package = tmp_path / source_root / "app"
    (package / "config.py").write_text("")
    (package / "main.py").write_text(
        f"from importlib.resources import files\nbase = files({anchor})\n"
        "asset = base / 'model.dat'\ndef main(): return asset.read_bytes()\n"
    )
    assert relative in {item.path for item in assess(tmp_path).resources}


@pytest.mark.parametrize("state", ["secret", "dirty", "untracked"])
@pytest.mark.usefixtures("fake_preparation")
def test_assigned_resource_security_and_provenance(tmp_path, monkeypatch, state):
    source = tmp_path / "source"
    relative = as_file_project(source)
    (source / "src/app/main.py").write_text(
        "from importlib.resources import files, as_file\nfrom os import getenv\n"
        "PASSWORD=getenv('DB_PASSWORD')\nasset=files('app') / 'model.dat'\n"
        "def main(): return as_file(asset)\n"
    )
    secret = "PDBAssignedResourceSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    if state == "secret":
        (source / relative).write_text(secret)
    else:

        def git(*args):
            subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)

        git("init")
        git("add", ".")
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
            (source / relative).write_text("CHANGED")
        else:
            git("rm", "--cached", relative)
    with pytest.raises(PreparationError) as error:
        generate_deployment_kit(repo(source), tmp_path / "kit", bootstrap_mode="online_cmd")
    assert secret not in str(error.value)
    assert not (tmp_path / "kit").exists()


@pytest.mark.usefixtures("fake_preparation")
@pytest.mark.parametrize("consumer", ["asset.read_bytes()", "as_file(asset)"])
def test_assigned_resource_generation_and_static_parity(tmp_path, consumer):
    source = tmp_path / "source"
    relative = as_file_project(source)
    (source / "src/app/main.py").write_text(
        "from importlib.resources import files, as_file\n"
        f"asset=files('app') / 'model.dat'\ndef main(): return {consumer}\n"
    )
    kit = tmp_path / "kit"
    generate_deployment_kit(repo(source), kit, bootstrap_mode="online_cmd")
    assert (kit / relative).read_bytes() == b"model fixture"
    assert validate_static_kit(kit).final_state.value == "STATIC_VALID"
    assert (
        json.loads((kit / "deployment/manifest.json").read_text())["application_artifact"] is None
    )
    code = "import sys; sys.path.insert(0, sys.argv[1]); from app.main import main; "
    if consumer == "asset.read_bytes()":
        code += "assert main() == b'model fixture'"
    else:
        code += "exec(\"with main() as path:\\n assert path.read_bytes() == b'model fixture'\")"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(kit / "src")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "consumer",
    [
        "as_file(directory)",
        "asset.read_bytes()",
        "directory.joinpath('weights.bin').read_bytes()",
    ],
)
def test_assigned_directory_and_chained_descendants(tmp_path, consumer):
    as_file_project(tmp_path)
    directory = tmp_path / "src/app/bundle"
    directory.mkdir()
    (directory / "weights.bin").write_bytes(b"MODEL")
    (tmp_path / "src/app/main.py").write_text(
        "from importlib.resources import files, as_file\n"
        "base=files('app')\ndirectory=base / 'bundle'\nasset=directory / 'weights.bin'\n"
        f"def main(): return {consumer}\n"
    )
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "src/app/bundle/weights.bin" in _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize("namespace", [False, True])
def test_assigned_longest_parent_mapping(tmp_path, namespace):
    as_file_project(tmp_path, source_root="lib", mapping="{'app'='lib/app','app.child'='code'}")
    directory = tmp_path / "code"
    directory.mkdir()
    (directory / "config.py").write_text("")
    if not namespace:
        (directory / "__init__.py").write_text("")
    (directory / "model.dat").write_text("MODEL")
    (tmp_path / "lib/app/main.py").write_text(
        "from importlib.resources import files\nbase=files('app.child.config')\n"
        "asset=base / 'model.dat'\ndef main(): return asset.read_bytes()\n"
    )
    assert "code/model.dat" in {item.path for item in assess(tmp_path).resources}


def test_assigned_resource_containment(tmp_path, monkeypatch):
    source = tmp_path / "source"
    relative = as_file_project(source)
    (source / "src/app/main.py").write_text(
        "from importlib.resources import files\nasset=files('app') / 'model.dat'\n"
        "def main(): return asset.read_bytes()\n"
    )
    target = source / relative
    outside = tmp_path / "outside.dat"
    outside.write_text("OUTSIDE")
    original = Path.resolve
    monkeypatch.setattr(
        Path, "resolve", lambda p, *a, **kw: outside if p == target else original(p, *a, **kw)
    )
    assert not any(
        item.path == relative and item.role.value == "runtime_resource"
        for item in assess(source).file_inventory
    )
