"""Existing project tables own omitted non-dynamic metadata fields too."""

import pytest
from test_dependency_authority import assess, write_project
from test_generation import _make_application_wheel, _write_mapped_project

from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import validate_application_wheel
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.planning.planner import create_deployment_plan


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_omitted_dependencies_are_authoritative_empty(tmp_path, legacy):
    write_project(tmp_path, legacy, None)
    assessment = assess(tmp_path)
    assert assessment.dependencies == []
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" not in plan.risk_gate.blocking_codes
    assert plan.lock_graph.dependencies == []


def add_legacy_entry(root, legacy, group):
    path = root / legacy
    if legacy == "setup.cfg":
        path.write_text(path.read_text() + f"[options.entry_points]\n{group}=\n stale=old:main\n")
    else:
        path.write_text(
            path.read_text().replace(
                "setup(", f"setup(entry_points={{{group!r}: ['stale=old:main']}}, "
            )
        )


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("group", ["console_scripts", "gui_scripts"])
def test_omitted_script_groups_suppress_stale_launchers(tmp_path, legacy, group):
    write_project(tmp_path, legacy, "[]")
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text().split("[project.scripts]")[0])
    add_legacy_entry(tmp_path, legacy, group)
    assert inspect_metadata(tmp_path).project.entry_points == []


def test_omitted_requires_python_does_not_use_stale_setup_py(tmp_path):
    write_project(tmp_path, "setup.py", "[]")
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text().replace("requires-python='>=3.12'\n", ""))
    path = tmp_path / "setup.py"
    path.write_text(path.read_text().replace("setup(", "setup(python_requires='<3.10', "))
    assert inspect_metadata(tmp_path).python.requires_python is None


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("field", ["scripts", "gui-scripts"])
@pytest.mark.parametrize("static", [False, True])
def test_dynamic_script_evidence_is_retained_but_not_promised(tmp_path, legacy, field, static):
    write_project(tmp_path, legacy, "[]", dynamic=f"[{field!r}]")
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().split("[project.scripts]")[0]
        + (f"[project.{field}]\nmodern='app:main'\n" if static else "")
    )
    group = "console_scripts" if field == "scripts" else "gui_scripts"
    add_legacy_entry(tmp_path, legacy, group)
    assessment = assess(tmp_path)
    assert "stale" in {entry.name for entry in assessment.project.entry_points}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "ENTRYPOINT_METADATA_UNSUPPORTED" in plan.risk_gate.blocking_codes


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("group", ["console_scripts", "gui_scripts"])
def test_no_project_table_retains_legacy_launchers(tmp_path, legacy, group):
    write_project(tmp_path, legacy, None)
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text().split("[project]")[0])
    add_legacy_entry(tmp_path, legacy, group)
    assert {entry.name for entry in inspect_metadata(tmp_path).project.entry_points} == {"stale"}


@pytest.mark.parametrize("field", ["scripts", "gui-scripts"])
def test_dynamic_script_contract_stops_generation_before_uv(tmp_path, monkeypatch, field):
    source = tmp_path / "source"
    write_project(source, "setup.py", "[]", dynamic=f"[{field!r}]")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "kit"
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail("must stop before acquisition"),
    )
    preview = generate_deployment_kit(repository, output, dry_run=True).preview
    assert any("ENTRYPOINT_METADATA_UNSUPPORTED" in item for item in preview.developer_actions)
    with pytest.raises(PreparationError, match="ENTRYPOINT_METADATA_UNSUPPORTED"):
        generate_deployment_kit(repository, output, prepare_lock=True)
    assert not output.exists()


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_omitted_optional_groups_do_not_gain_legacy_extras(tmp_path, legacy):
    write_project(tmp_path, legacy, "[]")
    path = tmp_path / legacy
    if legacy == "setup.cfg":
        path.write_text(path.read_text() + "[options.extras_require]\nmap=obsolete>=1\n")
    else:
        path.write_text(
            path.read_text().replace("setup(", "setup(extras_require={'map':['obsolete']}, ")
        )
    metadata = inspect_metadata(tmp_path)
    assert metadata.project.optional_dependency_groups == {}
    assert metadata.dependencies == []


def test_custom_entry_point_group_is_not_a_console_or_gui_launcher(tmp_path):
    write_project(tmp_path, "setup.py", "[]")
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().split("[project.scripts]")[0]
        + "[project.entry-points.'some.group']\nplugin='app:main'\n"
    )
    assert inspect_metadata(tmp_path).project.entry_points == []


@pytest.mark.parametrize("project_present", [False, True])
def test_requires_python_pipfile_fallback_obeys_project_authority(tmp_path, project_present):
    write_project(tmp_path, "setup.py", "[]")
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().replace("requires-python='>=3.12'\n", "")
        if project_present
        else path.read_text().split("[project]")[0]
    )
    (tmp_path / "Pipfile").write_text("[requires]\npython_version='3.11'\n")
    assert inspect_metadata(tmp_path).python.requires_python == (
        None if project_present else "==3.11.*"
    )


def test_dynamic_requires_python_keeps_literal_backend_evidence(tmp_path):
    write_project(tmp_path, "setup.py", "[]", dynamic="['requires-python']")
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text().replace("requires-python='>=3.12'\n", ""))
    path = tmp_path / "setup.py"
    path.write_text(path.read_text().replace("setup(", "setup(python_requires='>=3.11', "))
    assert inspect_metadata(tmp_path).python.requires_python == ">=3.11"


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_omitted_gui_group_cannot_reject_correct_console_wheel(tmp_path, legacy):
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source, entry_group="scripts")
    if legacy == "setup.cfg":
        (source / legacy).write_text("[options.entry_points]\ngui_scripts=\n stale=old:main\n")
    else:
        (source / legacy).write_text(
            "from setuptools import setup\nsetup(entry_points={'gui_scripts':['stale=old:main']})\n"
        )
    assessment = assess(source)
    plan = create_deployment_plan(assessment, repository_root=source)
    assert plan.entry_point.declared_group == "console_scripts"
    wheel = _make_application_wheel(tmp_path, entry_group="console_scripts")
    artifact, _ = validate_application_wheel(
        wheel, assessment, plan, repository_root=source, validate_locked_dependencies=False
    )
    assert artifact.distribution_name == "mapped-app"
