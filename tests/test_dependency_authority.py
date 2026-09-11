"""Static PEP 621 dependency authority versus stale legacy install_requires."""

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.planning.extras import selected_dependencies
from python_deployment_builder.planning.planner import create_deployment_plan


def write_project(root, legacy, dependencies, obsolete="obsolete>=1", dynamic=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    field = f"dependencies={dependencies}\n" if dependencies is not None else ""
    if dynamic is not None:
        field += f"dynamic={dynamic}\n"
    (root / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools==79.0.1']\n"
        "build-backend='setuptools.build_meta'\n"
        "[project]\nname='demo'\nversion='1.0.0'\nrequires-python='>=3.12'\n"
        + field
        + "[project.scripts]\ndemo='app:main'\n",
        encoding="utf-8",
    )
    if legacy == "setup.cfg":
        contents = "[options]\npy_modules=app\ninstall_requires=\n    " + obsolete + "\n"
    else:
        contents = (
            "from setuptools import setup\n"
            f"setup(py_modules=['app'], install_requires=[{obsolete!r}])\n"
        )
    (root / legacy).write_text(contents, encoding="utf-8")
    (root / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
        "[[package]]\nname='demo'\nversion='1.0.0'\nsource={editable='.'}\n"
        + (
            "dependencies=[{name='modern'}]\n[[package]]\nname='modern'\nversion='2'\n"
            "wheels=[{url='https://example.invalid/modern-2-py3-none-any.whl'}]\n"
            if dependencies and "modern" in dependencies
            else ""
        ),
        encoding="utf-8",
    )


def assess(root):
    return assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("dependencies", ["['modern>=1']", "[]"])
def test_static_dependencies_override_stale_install_requires(tmp_path, legacy, dependencies):
    write_project(tmp_path, legacy, dependencies)
    assessment = assess(tmp_path)
    chosen = selected_dependencies(assessment, [], "3.12", "x86_64")
    expected = ["modern"] if "modern" in dependencies else []
    assert [item.distribution_name for item in chosen] == expected
    assert legacy in assessment.project.metadata_files
    assert assessment.project.py_modules == ["app"]
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" not in plan.risk_gate.blocking_codes
    assert [item.name for item in plan.lock_graph.dependencies] == expected


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("obsolete", ["modern>=2", "modern<2"])
def test_static_dependency_evidence_excludes_legacy_duplicate(tmp_path, legacy, obsolete):
    write_project(tmp_path, legacy, "['modern>=2']", obsolete)
    metadata = inspect_metadata(tmp_path)
    assert len(metadata.dependencies) == 1
    dependency = metadata.dependencies[0]
    assert dependency.declared_constraint == ">=2"
    assert [(item.file, item.detail) for item in dependency.evidence] == [
        ("pyproject.toml", "Declared in [project].dependencies.")
    ]


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("dependencies", ["'obsolete>=1'", "{}", "42", "[1]", "['modern', 1]"])
def test_malformed_standardized_dependencies_fail_without_legacy_fallback(
    tmp_path, legacy, dependencies
):
    write_project(tmp_path, legacy, dependencies)
    with pytest.raises(ValueError, match=r"\[project\].dependencies"):
        inspect_metadata(tmp_path)


@pytest.mark.parametrize("dependencies", ["[]", "['modern>=1']", None])
@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_dynamic_dependencies_retain_legacy_and_block(tmp_path, dependencies, legacy):
    write_project(tmp_path, legacy, dependencies, dynamic="['dependencies']")
    assessment = assess(tmp_path)
    assert "obsolete" in [d.distribution_name for d in assessment.dependencies]
    assert (
        "RUNTIME_SYNC_METADATA_UNSUPPORTED"
        in create_deployment_plan(assessment, repository_root=tmp_path).risk_gate.blocking_codes
    )


def test_static_dynamic_cannot_be_mistaken_for_complete_static_set(tmp_path):
    write_project(tmp_path, "setup.py", "['modern>=1']", "modern>=1", "['dependencies']")
    plan = create_deployment_plan(assess(tmp_path), repository_root=tmp_path)
    assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" in plan.risk_gate.blocking_codes


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_explicit_empty_gui_scripts_override_stale_legacy_launcher(tmp_path, legacy):
    write_project(tmp_path, legacy, "[]")
    with (tmp_path / "pyproject.toml").open("a") as stream:
        stream.write("[project.gui-scripts]\n")
    if legacy == "setup.cfg":
        with (tmp_path / legacy).open("a") as stream:
            stream.write("[options.entry_points]\ngui_scripts=\n    obsolete=old:main\n")
    else:
        path = tmp_path / legacy
        path.write_text(
            path.read_text().replace(
                "install_requires=['obsolete>=1']",
                "install_requires=['obsolete>=1'], "
                "entry_points={'gui_scripts':['obsolete=old:main']}",
            )
        )
    assessment = assess(tmp_path)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert plan.entry_point.target == "app:main"
    assert len(assessment.project.entry_points) == 1


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("build_system_only", [False, True])
def test_genuine_legacy_dependencies_still_block(tmp_path, legacy, build_system_only):
    write_project(tmp_path, legacy, None)
    if build_system_only:
        path = tmp_path / "pyproject.toml"
        path.write_text(path.read_text().split("[project]")[0])
        path = tmp_path / legacy
        if legacy == "setup.cfg":
            path.write_text("[metadata]\nname=demo\nversion=1.0.0\n" + path.read_text())
        else:
            path.write_text(
                path.read_text().replace("setup(", "setup(name='demo', version='1.0.0', ")
            )
    assessment = assess(tmp_path)
    assert [d.distribution_name for d in assessment.dependencies] == ["obsolete"]
    assert {e.file for e in assessment.dependencies[0].evidence} == {legacy}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" in plan.risk_gate.blocking_codes


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_unrelated_dynamic_field_does_not_reactivate_legacy_dependencies(tmp_path, legacy):
    write_project(tmp_path, legacy, "[]", dynamic="['description']")
    assert inspect_metadata(tmp_path).dependencies == []


@pytest.mark.parametrize("dynamic", ["'dependencies'", "{}", "[1]"])
def test_malformed_dynamic_declaration_fails_controlled(tmp_path, dynamic):
    write_project(tmp_path, "setup.cfg", "[]", dynamic=dynamic)
    with pytest.raises(ValueError, match=r"\[project\].dynamic"):
        inspect_metadata(tmp_path)


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_selected_optional_and_entry_point_extras_are_unchanged(tmp_path, legacy):
    write_project(tmp_path, legacy, "[]")
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().replace("app:main", "app:main [map]")
        + "[project.optional-dependencies]\nmap=['modern>=1']\n"
    )
    (tmp_path / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='>=3.12'\n"
        "[[package]]\nname='demo'\nversion='1.0.0'\nsource={editable='.'}\n"
        "[package.optional-dependencies]\nmap=[{name='modern'}]\n"
        "[[package]]\nname='modern'\nversion='2'\n"
        "wheels=[{url='https://example.invalid/modern-2-py3-none-any.whl'}]\n"
    )
    assessment = assess(tmp_path)
    assert selected_dependencies(assessment, [], "3.12", "x86_64") == []
    assert [
        d.distribution_name for d in selected_dependencies(assessment, ["map"], "3.12", "x86_64")
    ] == ["modern"]
    unselected = create_deployment_plan(assessment, repository_root=tmp_path)
    assert "ENTRYPOINT_EXTRA_NOT_SELECTED" in unselected.risk_gate.blocking_codes
    selected = create_deployment_plan(assessment, repository_root=tmp_path, selected_extras=["map"])
    assert "ENTRYPOINT_EXTRA_NOT_SELECTED" not in selected.risk_gate.blocking_codes
    assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" not in selected.risk_gate.blocking_codes
    assert [d.name for d in selected.lock_graph.dependencies] == ["modern"]


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
def test_standardized_core_identity_fields_already_win(tmp_path, legacy):
    write_project(tmp_path, legacy, "[]")
    path = tmp_path / legacy
    if legacy == "setup.cfg":
        path.write_text(
            "[metadata]\nname=old\nversion=0.1\n" + path.read_text() + "python_requires=<3.10\n"
        )
    else:
        path.write_text(
            path.read_text().replace(
                "setup(", "setup(name='old', version='0.1', python_requires='<3.10', "
            )
        )
    metadata = inspect_metadata(tmp_path)
    project = metadata.project
    assert project.distribution_name == "demo"
    assert project.version == "1.0.0"
    assert metadata.python.requires_python == ">=3.12"


@pytest.mark.parametrize("legacy", ["setup.cfg", "setup.py"])
@pytest.mark.parametrize("group", ["console_scripts", "gui_scripts"])
@pytest.mark.parametrize("empty", [False, True])
def test_static_script_group_suppresses_only_its_legacy_group(tmp_path, legacy, group, empty):
    write_project(tmp_path, legacy, "[]")
    field = "scripts" if group == "console_scripts" else "gui-scripts"
    other = "gui_scripts" if group == "console_scripts" else "console_scripts"
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().split("[project.scripts]")[0]
        + f"[project.{field}]\n"
        + ("" if empty else "demo='app:main'\n")
    )
    path = tmp_path / legacy
    if legacy == "setup.cfg":
        path.write_text(
            path.read_text()
            + "[options.entry_points]\n"
            + f"{group}=\n    stale=old:main\n{other}=\n    retained=app:main\n"
        )
    else:
        path.write_text(
            path.read_text().replace(
                "setup(",
                f"setup(entry_points={{{group!r}: ['stale=old:main'], "
                f"{other!r}: ['retained=app:main']}}, ",
            )
        )
    names = {entry.name for entry in inspect_metadata(tmp_path).project.entry_points}
    assert names == ({"retained"} if empty else {"demo", "retained"})


@pytest.mark.parametrize("dependencies", ["['modern>=1']", None])
def test_dynamic_contract_without_literal_additions_blocks_before_generation(
    tmp_path, monkeypatch, dependencies
):
    source = tmp_path / "source"
    write_project(source, "setup.cfg", dependencies, dynamic="['dependencies']")
    (source / "setup.cfg").write_text("[options]\npy_modules=app\n")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "kit"
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail("dynamic metadata must block before uv acquisition"),
    )
    preview = generate_deployment_kit(repository, output, dry_run=True).preview
    assert any("RUNTIME_SYNC_METADATA_UNSUPPORTED" in item for item in preview.developer_actions)
    assert not output.exists()
    with pytest.raises(PreparationError, match="RUNTIME_SYNC_METADATA_UNSUPPORTED"):
        generate_deployment_kit(repository, output, prepare_lock=True)
    assert not output.exists()
