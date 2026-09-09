from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.imports import scan_imports
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import (
    package_surface_resolved,
    resolve_package_data_members,
    resolve_packaged_python_sources,
)
from python_deployment_builder.cli import main
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.models import (
    FindingStatus,
    OnlineCompatibilityAssessment,
    OnlineIndexContext,
    PackagingAssessment,
    RepositoryFileRole,
    WheelCompatibility,
)
from python_deployment_builder.planning.planner import create_deployment_plan


def _repository(root: Path) -> MaterializedRepository:
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def _write_legacy_app(root: Path) -> None:
    (root / "requirements-core.txt").write_text("Pillow>=10\nGDAL>=3\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from PIL import Image\nfrom osgeo import gdal\n\ndef main():\n    return Image, gdal\n",
        encoding="utf-8",
    )


def _write_fingerprint_app(root: Path) -> None:
    (root / "assets").mkdir()
    (root / "docs").mkdir()
    (root / "examples").mkdir()
    (root / "tests").mkdir()
    (root / "deployment").mkdir()
    (root / "historical").mkdir()
    (root / ".gitignore").write_text("historical/\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """[project]
name = "fingerprint-app"
version = "1.0.0"
dependencies = ["Pillow"]
[project.scripts]
fingerprint-app = "app:main"
""",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("Pillow\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / "assets/view.html").write_text("<p>runtime</p>\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from pathlib import Path\n"
        "VIEW = Path(__file__).parent / 'assets/view.html'\n"
        "def main():\n    return VIEW.read_text()\n",
        encoding="utf-8",
    )
    for path in (
        root / "docs/snippet.py",
        root / "examples/example.py",
        root / "tests/test_app.py",
        root / "deployment/helper.py",
        root / "historical/old.py",
    ):
        path.write_text("VALUE = 1\n", encoding="utf-8")


def test_role_scope_respects_gitignore_and_excludes_non_runtime_python(tmp_path: Path) -> None:
    _write_legacy_app(tmp_path)
    (tmp_path / ".gitignore").write_text("historical/\nlocal/**/*.py\n", encoding="utf-8")
    for directory in ("historical", "local/nested", "docs", "tests", "examples", "deployment"):
        (tmp_path / directory).mkdir(parents=True)
    alarming = "import nonexistent_runtime\nsubprocess.run(['ImageMagick'])\n"
    (tmp_path / "historical/old.py").write_text(alarming, encoding="utf-8")
    (tmp_path / "local/nested/tool.py").write_text(alarming, encoding="utf-8")
    (tmp_path / "docs/snippet.py").write_text(alarming, encoding="utf-8")
    (tmp_path / "tests/test_app.py").write_text(alarming, encoding="utf-8")
    (tmp_path / "examples/demo.py").write_text(alarming, encoding="utf-8")
    (tmp_path / "deployment/setup_environment.py").write_text(alarming, encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert {item.import_name for item in assessment.imports} >= {"PIL", "osgeo"}
    assert "nonexistent_runtime" not in {item.import_name for item in assessment.imports}
    assert not any(item.name == "ImageMagick" for item in assessment.runtime_requirements)
    roles = {item.path: item.role for item in assessment.file_inventory}
    assert roles["docs/snippet.py"] == RepositoryFileRole.DOCUMENTATION
    assert roles["tests/test_app.py"] == RepositoryFileRole.TEST
    assert roles["examples/demo.py"] == RepositoryFileRole.EXAMPLE_OR_SNIPPET
    assert roles["deployment/setup_environment.py"] == RepositoryFileRole.DEPLOYMENT_SUPPORT
    assert assessment.analysis_scope.ignored_local_excluded >= 2


def test_ignored_resource_referenced_by_application_is_blocking(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("private-assets/\n", encoding="utf-8")
    (tmp_path / "private-assets").mkdir()
    (tmp_path / "private-assets/settings.json").write_text("{}", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from pathlib import Path\n"
        "SETTINGS = Path(__file__).parent / 'private-assets/settings.json'\n"
        "SETTINGS.read_text()\n",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))

    assert any(item.path == "private-assets/settings.json" for item in assessment.resources)
    assert "RUNTIME_DEPENDENCY_IS_IGNORED" in {item.code for item in assessment.risks}


def test_nested_ignore_negation_reincludes_application_source(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(
        "generated/**/*.py\n!generated/kept.py\n", encoding="utf-8"
    )
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated/ignored.py").write_text("import old_dependency\n", encoding="utf-8")
    (tmp_path / "generated/kept.py").write_text("import tkinter\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    roles = {item.path: item.role for item in assessment.file_inventory}

    assert roles["generated/ignored.py"] == RepositoryFileRole.IGNORED_OR_LOCAL
    assert roles["generated/kept.py"] == RepositoryFileRole.APPLICATION_SOURCE
    assert "old_dependency" not in {item.import_name for item in assessment.imports}
    assert "tkinter" in {item.import_name for item in assessment.imports}


def test_resource_and_mutable_state_evidence_are_static(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets/icon.png").write_bytes(b"png")
    (tmp_path / "view.html").write_text("<html></html>", encoding="utf-8")
    (tmp_path / "settings.json").write_text("{}", encoding="utf-8")
    (tmp_path / "state.json").write_text("{}", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
ICON = Path(__file__).parent / "assets/icon.png"
VIEW = Path(__file__).with_name("view.html")
SETTINGS = Path(__file__).with_name("settings.json")
STATE = Path(__file__).with_name("state.json")
def load():
    return ICON.read_bytes(), VIEW.read_text(), SETTINGS.read_text()
def save():
    STATE.write_text("saved")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))

    resource_paths = {item.path for item in assessment.resources}
    assert {"assets/icon.png", "view.html", "settings.json"} <= resource_paths
    assert "state.json" not in resource_paths
    state = next(item for item in assessment.file_inventory if item.path == "state.json")
    assert state.role == RepositoryFileRole.MUTABLE_STATE_CANDIDATE
    assert any(item.classification == "project_local" for item in assessment.write_locations)
    assert "SOURCE_ADJACENT_MUTABLE_STATE" in {item.code for item in assessment.structural_guidance}


def test_import_contexts_and_conservative_distribution_mappings(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "Pillow\nPyMuPDF\nGDAL\nrequests\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        """from typing import TYPE_CHECKING
from PIL import Image
if TYPE_CHECKING:
    import fitz
if __debug__:
    from osgeo import gdal
def feature():
    import requests
""",
        encoding="utf-8",
    )
    metadata = inspect_metadata(tmp_path)

    result = scan_imports(tmp_path, ["."], metadata.dependencies)
    by_name = {item.import_name: item for item in result.observations}

    assert by_name["PIL"].distribution_name == "Pillow"
    assert by_name["fitz"].distribution_name == "PyMuPDF"
    assert by_name["osgeo"].distribution_name == "GDAL"
    assert by_name["fitz"].contexts == ["type_checking"]
    assert by_name["osgeo"].contexts == ["conditional"]
    assert by_name["requests"].contexts == ["deferred"]


def test_entrypoint_candidates_are_diagnostic_and_never_execute_target(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    (tmp_path / "gui.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
        "import tkinter as tk\ndef main():\n    return tk.Tk\n",
        encoding="utf-8",
    )
    (tmp_path / "launch.py").write_text(
        "from gui import main\nif __name__ == '__main__':\n    main()\n", encoding="utf-8"
    )

    assessment = assess_repository(_repository(tmp_path))

    candidate = next(item for item in assessment.entry_point_candidates if item.path == "launch.py")
    assert candidate.target == "gui:main"
    assert candidate.kind == "gui"
    assert not candidate.authoritative
    assert not marker.exists()


def test_multiple_candidates_stay_non_authoritative_and_declared_entrypoint_wins(
    tmp_path: Path,
) -> None:
    for name in ("one", "two"):
        (tmp_path / f"{name}.py").write_text(
            "def main():\n    return None\nif __name__ == '__main__':\n    main()\n",
            encoding="utf-8",
        )
    assessment = assess_repository(_repository(tmp_path))
    assert len(assessment.entry_point_candidates) == 2
    assert not assessment.project.entry_points

    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "declared-app"
version = "1.0.0"
dependencies = []
[project.gui-scripts]
declared = "two:main"
""",
        encoding="utf-8",
    )
    declared = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(declared)
    assert plan.entry_point is not None
    assert plan.entry_point.target == "two:main"


def test_candidate_detection_unwraps_system_exit_and_src_layout(tmp_path: Path) -> None:
    source = tmp_path / "src" / "sample"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("", encoding="utf-8")
    (source / "gui.py").write_text(
        "def main():\n    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    candidate = assessment.entry_point_candidates[0]

    assert candidate.target == "sample.gui:main"


def test_missing_entrypoint_produces_report_and_all_typed_blockers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_legacy_app(tmp_path)
    reports = tmp_path.parent / f"{tmp_path.name}-reports"

    result = main(["plan", str(tmp_path), "--output-dir", str(reports)])
    capsys.readouterr()
    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)

    assert result == 1
    assert (reports / "deployment-plan.json").is_file()
    assert (reports / "deployment-plan.md").is_file()
    assert plan.entry_point is None
    assert plan.readiness.state == "BLOCKED_PENDING_ENTRYPOINT"
    assert {"ENTRYPOINT_DECLARATION_REQUIRED", "LOCKFILE_GENERATION_REQUIRED"} <= set(
        plan.readiness.blocker_codes
    )
    with pytest.raises(PreparationError, match="authoritative standardized"):
        generate_deployment_kit(_repository(tmp_path), tmp_path.parent / "kit")

    workflow = tmp_path.parent / f"{tmp_path.name}-workflow"
    assert main(["all", str(tmp_path), "--output-dir", str(workflow)]) == 2
    output = capsys.readouterr().out
    assert "ENTRYPOINT_DECLARATION_REQUIRED" in output
    assert "LOCKFILE_GENERATION_REQUIRED" in output
    assert (workflow / "reports" / "deployment-plan.json").is_file()
    assert not (workflow / "deployment-kit").exists()


def test_online_plan_inspects_known_legacy_groups_without_selecting_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_legacy_app(tmp_path)
    captured: list[str] = []

    def fake_inspection(dependencies, versions, architecture):
        captured.extend(item.distribution_name for item in dependencies)
        return OnlineCompatibilityAssessment(
            context=OnlineIndexContext(
                assessed_at=datetime.now(UTC),
                index_name="test",
                index_url="https://example.invalid",
                python_targets=versions,
                windows_architecture=architecture,
            )
        )

    monkeypatch.setattr(
        "python_deployment_builder.planning.planner.inspect_dependency_wheels",
        fake_inspection,
    )
    plan = create_deployment_plan(assess_repository(_repository(tmp_path)), online=True)

    assert set(captured) == {"Pillow", "GDAL"}
    assert plan.entry_point is None


def test_deployment_support_vendor_evidence_is_separate_and_evidence_driven(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("import tkinter\n", encoding="utf-8")
    (tmp_path / "deployment").mkdir()
    (tmp_path / "deployment/setup_environment.py").write_text(
        "import winreg\n"
        "# SOFTWARE\\ESRI\\ArcGISPro arcgispro-py3 arcpy clone environment WebView2\n",
        encoding="utf-8",
    )
    (tmp_path / "deployment/constraints.txt").write_text("proxy_tools==0.1.0\n", encoding="utf-8")
    assessment = assess_repository(_repository(tmp_path))

    assert assessment.deployment_support
    assert {item.name for item in assessment.vendor_runtimes} == {
        "ArcGIS Pro",
        "Microsoft Edge WebView2 Runtime",
    }
    assert assessment.deployment_support_dependencies[0].distribution_name == "proxy_tools"
    assert not any(item.import_name == "winreg" for item in assessment.imports)
    assert "EXISTING_DEPLOYMENT_COLLISION_POTENTIAL" in {item.code for item in assessment.risks}
    assert "VENDOR_RUNTIME_BACKEND_UNSUPPORTED" in {
        item.code for item in assessment.structural_guidance
    }

    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "app.py").write_text("import tkinter\n", encoding="utf-8")
    unrelated_assessment = assess_repository(_repository(unrelated))
    assert not unrelated_assessment.vendor_runtimes
    assert not any("ArcGIS" in item.title for item in unrelated_assessment.structural_guidance)


def test_legacy_requirement_aggregate_and_unusual_runtime_import_are_reported(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements-core.txt").write_text("Pillow\n", encoding="utf-8")
    (tmp_path / "requirements-all.txt").write_text(
        "-r requirements-core.txt\npywebview\n", encoding="utf-8"
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("from docs import helper\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    groups = {item.name: item for item in assessment.project.legacy_dependency_groups}

    assert groups["all"].aggregate_of == ["core"]
    assert not groups["all"].authoritative_selectable_extra
    assert "APPLICATION_IMPORTS_NON_RUNTIME_SCOPE" in {item.code for item in assessment.risks}


def test_repository_fingerprint_tracks_deployment_inputs_not_excluded_roles(
    tmp_path: Path,
) -> None:
    _write_fingerprint_app(tmp_path)
    original = assess_repository(_repository(tmp_path)).repository.fingerprint

    excluded = (
        "docs/snippet.py",
        "examples/example.py",
        "tests/test_app.py",
        "deployment/helper.py",
        "historical/old.py",
    )
    for relative in excluded:
        path = tmp_path / relative
        before = path.read_text(encoding="utf-8")
        path.write_text(before + "CHANGED = True\n", encoding="utf-8")
        assert assess_repository(_repository(tmp_path)).repository.fingerprint == original
        path.write_text(before, encoding="utf-8")

    included = (
        "app.py",
        "assets/view.html",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
    )
    for relative in included:
        path = tmp_path / relative
        before = path.read_bytes()
        path.write_bytes(before + b"\n# fingerprint change\n")
        assert assess_repository(_repository(tmp_path)).repository.fingerprint != original
        path.write_bytes(before)


def test_nested_gitignore_rules_are_relative_and_do_not_require_git(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(
        "/root-only.txt\nignored/**/*.py\n!ignored/kept.py\n\\#literal.py\n\\!literal.py\n",
        encoding="utf-8",
    )
    (tmp_path / "subdir/deep").mkdir(parents=True)
    (tmp_path / "ignored").mkdir()
    (tmp_path / "subdir/.gitignore").write_text(
        "*.py\n!keep.py\n/deep-only.json\ndeep/**/*.json\n!deep/keep.json\n",
        encoding="utf-8",
    )
    for relative in (
        "root-only.txt",
        "subdir/root-only.txt",
        "#literal.py",
        "!literal.py",
        "ignored/old.py",
        "ignored/kept.py",
        "subdir/drop.py",
        "subdir/keep.py",
        "subdir/deep-only.json",
        "subdir/deep/drop.json",
        "subdir/deep/keep.json",
    ):
        (tmp_path / relative).write_text("VALUE = 1\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    roles = {item.path: item.role for item in assessment.file_inventory}

    for relative in (
        "root-only.txt",
        "#literal.py",
        "!literal.py",
        "ignored/old.py",
        "subdir/drop.py",
        "subdir/deep-only.json",
        "subdir/deep/drop.json",
    ):
        assert roles[relative] == RepositoryFileRole.IGNORED_OR_LOCAL
    assert roles["subdir/root-only.txt"] != RepositoryFileRole.IGNORED_OR_LOCAL
    assert roles["ignored/kept.py"] == RepositoryFileRole.APPLICATION_SOURCE
    assert roles["subdir/keep.py"] == RepositoryFileRole.APPLICATION_SOURCE
    assert roles["subdir/deep/keep.json"] != RepositoryFileRole.IGNORED_OR_LOCAL
    assert not (tmp_path / ".git").exists()


def test_runtime_evidence_promotes_generic_roles_but_not_ignored_content(tmp_path: Path) -> None:
    for directory in ("docs", "examples", "deployment", "ignored"):
        (tmp_path / directory).mkdir()
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "docs/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "deployment/helper.py").write_text("VALUE = 2\n", encoding="utf-8")
    (tmp_path / "docs/runtime_template.html").write_text("docs", encoding="utf-8")
    (tmp_path / "examples/config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ignored/private-template.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ignored/private_module.py").write_text("VALUE = 3\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
from docs import helper
from deployment import helper as deployment_helper
from ignored import private_module
BASE = Path(__file__).parent
def load():
    return (
        helper.VALUE,
        deployment_helper.VALUE,
        private_module.VALUE,
        (BASE / "docs/runtime_template.html").read_text(),
        (BASE / "examples/config.json").read_text(),
        (BASE / "ignored/private-template.json").read_text(),
    )
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    roles = {item.path: item.role for item in assessment.file_inventory}

    assert roles["docs/helper.py"] == RepositoryFileRole.APPLICATION_SOURCE
    assert roles["deployment/helper.py"] == RepositoryFileRole.APPLICATION_SOURCE
    assert roles["docs/runtime_template.html"] == RepositoryFileRole.RUNTIME_RESOURCE
    assert roles["examples/config.json"] == RepositoryFileRole.RUNTIME_RESOURCE
    assert roles["ignored/private-template.json"] == RepositoryFileRole.IGNORED_OR_LOCAL
    assert roles["ignored/private_module.py"] == RepositoryFileRole.IGNORED_OR_LOCAL
    ignored_risk = next(
        item for item in assessment.risks if item.code == "RUNTIME_DEPENDENCY_IS_IGNORED"
    )
    assert "ignored/private-template.json" in ignored_risk.description
    assert "ignored/private_module.py" in ignored_risk.description
    assert "APPLICATION_IMPORTS_GENERATION_EXCLUDED_SCOPE" in {
        item.code for item in assessment.risks
    }
    assert assessment.rating == "RED"

    fingerprint = assessment.repository.fingerprint
    (tmp_path / "docs/helper.py").write_text("VALUE = 10\n", encoding="utf-8")
    assert assess_repository(_repository(tmp_path)).repository.fingerprint != fingerprint
    (tmp_path / "docs/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "ignored/private_module.py").write_text("VALUE = 30\n", encoding="utf-8")
    assert assess_repository(_repository(tmp_path)).repository.fingerprint == fingerprint


def test_resource_discovery_requires_path_use_and_tracks_access_modes(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    for relative, contents in (
        ("unused.png", "unused"),
        ("read.json", "{}"),
        ("write.json", "{}"),
        ("both.json", "{}"),
        ("icon.ico", "icon"),
        ("photo.png", "photo"),
        ("loop.png", "loop"),
        ("view.html", "<html></html>"),
        ("child.html", "<html></html>"),
        ("oauth-session.json", "TOP-SECRET-CONTENTS"),
    ):
        (tmp_path / "assets" / relative).write_text(contents, encoding="utf-8")
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
import os
import multiprocessing as mp
import tkinter as tk
import webview
BASE = Path(__file__).parent / "assets"
UNUSED = Path("assets/unused.png")
SPECS = [("loop", BASE / "loop.png")]
def paths(name):
    (BASE / "read.json").read_text()
    (BASE / "write.json").write_text("updated")
    with open(BASE / "both.json", "r+") as stream:
        stream.read()
    root = tk.Tk()
    root.iconbitmap(BASE / "icon.ico")
    tk.PhotoImage(file=BASE / "photo.png")
    webview.create_window("view", (BASE / "view.html").as_uri())
    for _, image in SPECS:
        image.read_bytes()
    mp.Process(target=print, args=(BASE / "child.html",))
    os.listdir(BASE)
    open(BASE / "oauth-session.json", "w").write("secret")
    open(BASE / "missing.json").read()
    open(BASE / name / "dynamic.json").read()
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    resources = {item.path: item for item in assessment.resources}
    inventory = {item.path: item for item in assessment.file_inventory}
    serialized = assessment.model_dump_json()

    assert "assets/unused.png" not in resources
    assert resources["assets/read.json"].access_mode == "read"
    assert inventory["assets/write.json"].role == RepositoryFileRole.MUTABLE_STATE_CANDIDATE
    assert inventory["assets/both.json"].role == RepositoryFileRole.MUTABLE_STATE_CANDIDATE
    assert inventory["assets/oauth-session.json"].role == RepositoryFileRole.MUTABLE_STATE_CANDIDATE
    assert {
        "assets/icon.ico",
        "assets/photo.png",
        "assets/loop.png",
        "assets/view.html",
        "assets/child.html",
        "assets",
    } <= set(resources)
    assert resources["assets/missing.json"].status == FindingStatus.NEEDS_VALIDATION
    assert any(item.status == FindingStatus.NEEDS_VALIDATION for item in resources.values())
    assert "TOP-SECRET-CONTENTS" not in serialized


def test_entrypoint_candidate_scope_and_confidence_resist_utilities(tmp_path: Path) -> None:
    for directory in ("docs", "tests", "deployment", "tools", "package"):
        (tmp_path / directory).mkdir()
    launcher = "def main():\n    return 0\nif __name__ == '__main__':\n    main()\n"
    (tmp_path / "docs/example.py").write_text(launcher, encoding="utf-8")
    (tmp_path / "tests/runner.py").write_text(launcher, encoding="utf-8")
    (tmp_path / "deployment/setup.py").write_text(launcher, encoding="utf-8")
    (tmp_path / "tools/migrate.py").write_text(launcher, encoding="utf-8")
    (tmp_path / "package/__main__.py").write_text(launcher, encoding="utf-8")
    (tmp_path / "dormant.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    (tmp_path / "gui.py").write_text(
        "import tkinter as tk\nif __name__ == '__main__':\n    tk.Tk()\n",
        encoding="utf-8",
    )

    candidates = {
        item.path: item for item in assess_repository(_repository(tmp_path)).entry_point_candidates
    }

    assert not {"docs/example.py", "tests/runner.py", "deployment/setup.py", "dormant.py"} & set(
        candidates
    )
    assert candidates["tools/migrate.py"].confidence == "low"
    assert candidates["package/__main__.py"].confidence == "medium"
    assert candidates["gui.py"].confidence == "high"
    assert candidates["gui.py"].target == "tkinter:Tk"
    assert all(not item.authoritative for item in candidates.values())


def test_multiple_blockers_preserve_primary_state_and_all_details(tmp_path: Path) -> None:
    source = Path(__file__).parent / "fixtures" / "optional_map_app"
    shutil.copytree(source, tmp_path, dirs_exist_ok=True)
    pyproject = tmp_path / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    text = text.replace(
        '\n[project.gui-scripts]\noptional-map-app = "optional_map_gui:main"\n', "\n"
    )
    pyproject.write_text(text, encoding="utf-8")
    (tmp_path / ".gitignore").write_text("private.json\n", encoding="utf-8")
    (tmp_path / "private.json").write_text("{}", encoding="utf-8")
    gui = tmp_path / "optional_map_gui.py"
    gui.write_text(
        gui.read_text(encoding="utf-8")
        + "\nfrom pathlib import Path\nPath('private.json').read_text()\n",
        encoding="utf-8",
    )

    plan = create_deployment_plan(
        assess_repository(_repository(tmp_path)),
        selected_extras=["map"],
        repository_root=tmp_path,
    )

    assert plan.readiness.state == "BLOCKED"
    assert {
        "RUNTIME_DEPENDENCY_IS_IGNORED",
        "ENTRYPOINT_DECLARATION_REQUIRED",
        "SOURCE_ONLY_LOCKED_DEPENDENCY",
    } <= set(plan.readiness.blocker_codes)
    assert len(plan.readiness.blockers) >= 3
    assert all(code in plan.model_dump_json() for code in plan.readiness.blocker_codes)


def test_legacy_online_source_only_evidence_remains_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_legacy_app(tmp_path)

    def fake_inspection(dependencies, versions, architecture):
        return OnlineCompatibilityAssessment(
            context=OnlineIndexContext(
                assessed_at=datetime.now(UTC),
                index_name="test",
                index_url="https://example.invalid",
                python_targets=versions,
                windows_architecture=architecture,
            ),
            dependencies=[
                WheelCompatibility(
                    distribution_name=item.distribution_name,
                    declared_constraint=item.declared_constraint,
                    resolved_version="1.0.0",
                    python_version=versions[0],
                    wheel_available=False,
                    source_distribution_available=True,
                    status=FindingStatus.NEEDS_VALIDATION,
                    detail="Source distribution only.",
                )
                for item in dependencies
            ],
        )

    monkeypatch.setattr(
        "python_deployment_builder.planning.planner.inspect_dependency_wheels",
        fake_inspection,
    )
    plan = create_deployment_plan(assess_repository(_repository(tmp_path)), online=True)

    assert "SOURCE_ONLY_LOCKED_DISTRIBUTION" not in plan.readiness.blocker_codes
    assert all(
        item.deployment_selection == "informational_legacy_group"
        for item in plan.online_compatibility.dependencies
    )


def test_online_inspection_keeps_declared_runtime_selected_without_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "mixed-metadata-app"
version = "1.0.0"
dependencies = ["Pillow"]
""",
        encoding="utf-8",
    )
    (tmp_path / "requirements-legacy.txt").write_text("GDAL>=3\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("from PIL import Image\n", encoding="utf-8")

    def fake_inspection(dependencies, versions, architecture):
        return OnlineCompatibilityAssessment(
            context=OnlineIndexContext(
                assessed_at=datetime.now(UTC),
                index_name="test",
                index_url="https://example.invalid",
                python_targets=versions,
                windows_architecture=architecture,
            ),
            dependencies=[
                WheelCompatibility(
                    distribution_name=item.distribution_name,
                    declared_constraint=item.declared_constraint,
                    resolved_version="1.0.0",
                    python_version=versions[0],
                    wheel_available=item.distribution_name == "Pillow",
                    source_distribution_available=True,
                    status=FindingStatus.DETECTED,
                    detail="Test evidence.",
                )
                for item in dependencies
            ],
        )

    monkeypatch.setattr(
        "python_deployment_builder.planning.planner.inspect_dependency_wheels",
        fake_inspection,
    )

    plan = create_deployment_plan(assess_repository(_repository(tmp_path)), online=True)
    selection = {
        item.distribution_name: item.deployment_selection
        for item in plan.online_compatibility.dependencies
    }

    assert selection == {
        "GDAL": "informational_legacy_group",
        "Pillow": "selected",
    }


def test_analysis_roles_control_source_staging(tmp_path: Path) -> None:
    _write_fingerprint_app(tmp_path)
    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)

    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert "app.py" in staged
    assert "assets/view.html" in staged
    assert "docs/snippet.py" not in staged
    assert "examples/example.py" not in staged
    assert "tests/test_app.py" not in staged
    assert "deployment/helper.py" not in staged
    assert "historical/old.py" not in staged


def test_relative_imports_promote_test_scope_modules_and_stage_them(tmp_path: Path) -> None:
    (tmp_path / "src/app/tests").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/main.py").write_text(
        "from . import sibling\nfrom .tests import helper\nfrom .tests.helper import run\n\n"
        "def main(): return sibling.value() + helper.value() + run()\n",
        encoding="utf-8",
    )
    (tmp_path / "src/app/sibling.py").write_text("def value(): return 1\n", encoding="utf-8")
    (tmp_path / "src/app/tests/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/tests/helper.py").write_text(
        "from . import nested\ndef value(): return nested.value()\ndef run(): return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "src/app/tests/nested.py").write_text("def value(): return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'relative-import-app'\nversion = '1.0'\n"
        "[project.scripts]\nrelative-import-app = 'app.main:main'\n"
        "[tool.setuptools]\npackages = ['app']\npackage-dir = {'' = 'src'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    by_path = {item.path: item for item in assessment.file_inventory}
    for path in ("src/app/tests/__init__.py", "src/app/tests/helper.py", "src/app/tests/nested.py"):
        assert by_path[path].role == RepositoryFileRole.APPLICATION_SOURCE
        assert any(
            "Application source imports local module" in item.detail
            for item in by_path[path].evidence
        )
    assert "APPLICATION_IMPORTS_NON_RUNTIME_SCOPE" in {item.code for item in assessment.risks}
    plan = create_deployment_plan(assessment, repository_root=tmp_path)

    assert plan.deployment_mode == "source"
    staged = _staging_files(tmp_path, assessment, plan, include=True)
    assert {
        "src/app/sibling.py",
        "src/app/tests/__init__.py",
        "src/app/tests/helper.py",
        "src/app/tests/nested.py",
    } <= staged.keys()


def test_parent_relative_import_uses_source_root_package_context(tmp_path: Path) -> None:
    (tmp_path / "src/app/sub").mkdir(parents=True)
    (tmp_path / "src/app/shared").mkdir()
    for path in ("app/__init__.py", "app/sub/__init__.py", "app/shared/__init__.py"):
        (tmp_path / "src" / path).write_text("", encoding="utf-8")
    (tmp_path / "src/app/sub/main.py").write_text(
        "from ..shared import helper\ndef main(): return helper.value()\n", encoding="utf-8"
    )
    (tmp_path / "src/app/shared/helper.py").write_text("def value(): return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'parent-relative-app'\nversion = '1.0'\n"
        "[project.scripts]\nparent-relative-app = 'app.sub.main:main'\n"
        "[tool.setuptools]\npackages = ['app', 'app.sub']\npackage-dir = {'' = 'src'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    helper = next(
        item for item in assessment.file_inventory if item.path == "src/app/shared/helper.py"
    )

    assert helper.role == RepositoryFileRole.APPLICATION_SOURCE
    assert any("app.shared.helper" in item.detail for item in helper.evidence)


def test_package_initializers_use_their_containing_package_as_relative_context(
    tmp_path: Path,
) -> None:
    (tmp_path / "src/app/tests").mkdir(parents=True)
    (tmp_path / "src/app/sub").mkdir()
    (tmp_path / "src/app/shared").mkdir()
    (tmp_path / "src/app/__init__.py").write_text(
        "from .tests import helper\n", encoding="utf-8"
    )
    (tmp_path / "src/app/tests/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/tests/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "src/app/sub/__init__.py").write_text(
        "from . import sibling\nfrom ..shared import helper\n", encoding="utf-8"
    )
    (tmp_path / "src/app/sub/sibling.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "src/app/shared/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/shared/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'initializer-relative-app'\nversion = '1.0'\n"
        "[tool.setuptools]\npackages = ['app', 'app.sub']\npackage-dir = {'' = 'src'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    by_path = {item.path: item for item in assessment.file_inventory}

    for path in ("src/app/tests/__init__.py", "src/app/tests/helper.py"):
        assert by_path[path].role == RepositoryFileRole.APPLICATION_SOURCE
        assert any("app.tests" in item.detail for item in by_path[path].evidence)
    sibling = by_path["src/app/sub/sibling.py"]
    shared_helper = by_path["src/app/shared/helper.py"]
    assert any("app.sub.sibling" in item.detail for item in sibling.evidence)
    assert any("app.shared.helper" in item.detail for item in shared_helper.evidence)
    assert "APPLICATION_IMPORTS_NON_RUNTIME_SCOPE" in {item.code for item in assessment.risks}


@pytest.mark.parametrize(
    ("layout", "package_directory", "resource_path"),
    [
        ("flat", "app", "app/data/default.json"),
        ("src", "src/app", "src/app/data/default.json"),
        ("mapped", "code", "code/data/default.json"),
    ],
)
def test_authoritative_setuptools_package_data_is_promoted_and_staged(
    tmp_path: Path, layout: str, package_directory: str, resource_path: str
) -> None:
    package_root = tmp_path / package_directory
    (package_root / "data").mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "main.py").write_text(
        "import importlib.resources\n"
        "def main():\n"
        "    name = 'default.json'\n"
        "    return importlib.resources.files('app').joinpath('data', name).read_text()\n",
        encoding="utf-8",
    )
    (package_root / "data/default.json").write_text('{"default": true}\n', encoding="utf-8")
    setuptools = (
        "[tool.setuptools]\npackages = ['app']\n"
        "package-dir = {app = 'code'}\n"
        if layout == "mapped"
        else "[tool.setuptools]\npackages = ['app']\n"
        if layout == "flat"
        else "[tool.setuptools]\npackage-dir = {'' = 'src'}\npackages = ['app']\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'package-data-app'\nversion = '1.0.0'\ndependencies = []\n"
        "[project.scripts]\npackage-data-app = 'app.main:main'\n"
        + setuptools
        + "[tool.setuptools.package-data]\napp = ['data/*.json']\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (tmp_path / "unrelated.bin").write_bytes(b"not declared package data")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    source_plan = plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"
    staged = _staging_files(tmp_path, assessment, source_plan, include=True)
    resource = next(item for item in assessment.resources if item.path == resource_path)
    inventory = next(item for item in assessment.file_inventory if item.path == resource_path)
    original = assessment.repository.fingerprint

    assert plan.deployment_mode == ("source" if layout == "flat" else "package")
    assert resource.status == FindingStatus.DETECTED
    assert resource.packaging_status == "packaged"
    assert any("Authoritative setuptools package-data" in item.detail for item in resource.evidence)
    assert inventory.role == RepositoryFileRole.RUNTIME_RESOURCE
    assert "Authoritative setuptools package-data" in inventory.reason
    assert resource_path in staged
    assert "unrelated.bin" not in staged
    assert [
        (item.source_path, item.installed_member_path)
        for item in resolve_package_data_members(tmp_path, assessment.project)
    ] == [(resource_path, "app/data/default.json")]
    data = tmp_path / resource_path
    data.write_text('{"default": false}\n', encoding="utf-8")
    assert assess_repository(_repository(tmp_path)).repository.fingerprint != original


@pytest.mark.parametrize(
    ("imports", "files_call"),
    [
        ("import importlib.resources", "importlib.resources.files('app')"),
        ("import importlib.resources as ir", "ir.files('app')"),
        ("from importlib import resources", "resources.files('app')"),
        ("from importlib import resources as ir", "ir.files('app')"),
        ("from importlib.resources import files", "files('app')"),
        ("from importlib.resources import files as resource_files", "resource_files('app')"),
    ],
)
def test_importlib_resources_files_promotes_concrete_source_resource(
    tmp_path: Path, imports: str, files_call: str
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{"default": true}\n', encoding="utf-8")
    (package / "main.py").write_text(
        f"{imports}\n\ndef main():\n"
        f"    return {files_call}.joinpath('defaults.json').read_text(encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nresource-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    resource = next(item for item in assessment.resources if item.path == "src/app/defaults.json")
    inventory = next(item for item in assessment.file_inventory if item.path == resource.path)
    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert resource.packaging_status == "repository_adjacent"
    assert inventory.role == RepositoryFileRole.RUNTIME_RESOURCE
    assert "importlib.resources.files" in resource.evidence[-1].detail
    assert resource.path in staged


@pytest.mark.parametrize(
    ("imports", "resource_call"),
    [
        ("import importlib.resources", "importlib.resources.read_text('app', 'defaults.json')"),
        ("import importlib.resources as ir", "ir.read_binary('app', 'defaults.json')"),
        ("from importlib import resources", "resources.read_text('app', 'defaults.json')"),
        ("from importlib import resources as ir", "ir.open_binary('app', 'defaults.json')"),
        ("from importlib.resources import read_text", "read_text('app', 'defaults.json')"),
        (
            "from importlib.resources import read_binary as resource_read_binary",
            "resource_read_binary('app', 'defaults.json')",
        ),
        ("from importlib.resources import open_text", "open_text('app', 'defaults.json')"),
    ],
)
def test_legacy_importlib_resources_reads_promote_concrete_source_resource(
    tmp_path: Path, imports: str, resource_call: str
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{"default": true}\n', encoding="utf-8")
    (package / "main.py").write_text(
        f"{imports}\n\ndef main():\n    return {resource_call}\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'legacy-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nlegacy-resource-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    resource = next(item for item in assessment.resources if item.path == "src/app/defaults.json")
    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert resource.packaging_status == "repository_adjacent"
    assert resource.path in staged
    assert "importlib.resources." in resource.evidence[-1].detail


def test_legacy_importlib_resources_rejects_dynamic_and_escaping_members(tmp_path: Path) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{}\n', encoding="utf-8")
    (tmp_path / "src/secret.json").write_text('{}\n', encoding="utf-8")
    (package / "main.py").write_text(
        "from importlib.resources import read_text\n"
        "def main(name='defaults.json'):\n"
        "    read_text('app', name)\n"
        "    return read_text('app', '../secret.json')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'unsafe-legacy-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nunsafe-legacy-resource-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert all(item.path != "src/app/defaults.json" for item in assessment.resources)
    assert any(item.status == FindingStatus.NEEDS_VALIDATION for item in assessment.resources)


@pytest.mark.parametrize(
    ("imports", "resource_call"),
    [
        ("import pkgutil", "pkgutil.get_data('app', 'defaults.json')"),
        ("import pkgutil as pu", "pu.get_data('app', 'defaults.json')"),
        ("from pkgutil import get_data", "get_data('app', 'defaults.json')"),
        (
            "from pkgutil import get_data as resource_data",
            "resource_data('app', 'defaults.json')",
        ),
    ],
)
def test_pkgutil_get_data_promotes_concrete_package_resource(
    tmp_path: Path, imports: str, resource_call: str
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{"default": true}\n', encoding="utf-8")
    (package / "main.py").write_text(
        f"{imports}\n\ndef main():\n    return {resource_call}\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'pkgutil-app'\nversion = '1.0'\n"
        "[project.scripts]\npkgutil-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    resource = next(item for item in assessment.resources if item.path == "src/app/defaults.json")

    assert resource.packaging_status == "repository_adjacent"
    assert "pkgutil.get_data" in resource.evidence[-1].detail
    assert resource.path in _staging_files(tmp_path, assessment, plan, include=True)


def test_pkgutil_get_data_supports_nested_members_and_package_dir_mapping(
    tmp_path: Path,
) -> None:
    package = tmp_path / "lib/app"
    resource_path = package / "templates/defaults.json"
    resource_path.parent.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    resource_path.write_text("{}\n", encoding="utf-8")
    (package / "main.py").write_text(
        "import pkgutil\ndef main():\n"
        "    return pkgutil.get_data('app', 'templates/defaults.json')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='pkgutil-mapped'\nversion='1.0'\n"
        "[project.scripts]\npkgutil-mapped='app.main:main'\n"
        "[tool.setuptools]\npackage-dir={\"\"='lib'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert any(item.path == "lib/app/templates/defaults.json" for item in assessment.resources)


@pytest.mark.parametrize(
    ("anchor", "entry_point", "package_directories", "physical_package", "resource"),
    [
        ("app", "app.main:main", "{app='code'}", "code", "code/defaults.json"),
        (
            "app.sub",
            "app.sub.main:main",
            "{app='lib'}",
            "lib/sub",
            "lib/sub/defaults.json",
        ),
    ],
)
def test_pkgutil_get_data_uses_exact_and_parent_package_dir_mappings(
    tmp_path: Path,
    anchor: str,
    entry_point: str,
    package_directories: str,
    physical_package: str,
    resource: str,
) -> None:
    package = tmp_path / physical_package
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(
        "from pkgutil import get_data\n"
        f"def main(): return get_data('{anchor}', 'defaults.json')\n",
        encoding="utf-8",
    )
    (package / "defaults.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='pkgutil-exact-mapped'\nversion='1.0'\n"
        f"[project.scripts]\npkgutil-exact-mapped='{entry_point}'\n"
        "[tool.setuptools]\n"
        f"package-dir={package_directories}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert any(item.path == resource for item in assessment.resources)


def test_pkgutil_get_data_keeps_declared_package_data_package_backed(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(
        "import pkgutil\ndef main(): return pkgutil.get_data('app', 'defaults.json')\n",
        encoding="utf-8",
    )
    (package / "defaults.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='pkgutil-package-data'\nversion='1.0'\n"
        "[project.scripts]\npkgutil-package-data='app.main:main'\n"
        "[tool.setuptools]\npackages=['app']\npackage-dir={\"\"='src'}\n"
        "[tool.setuptools.package-data]\napp=['defaults.json']\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    resource = next(item for item in assessment.resources if item.path == "src/app/defaults.json")

    assert resource.packaging_status == "packaged"


def test_unrelated_get_data_function_does_not_receive_pkgutil_semantics(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text("{}\n", encoding="utf-8")
    (package / "main.py").write_text(
        "def get_data(package, resource): return None\n"
        "def main(): return get_data('app', 'defaults.json')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='unrelated-get-data'\nversion='1.0'\n"
        "[project.scripts]\nunrelated-get-data='app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert all(item.path != "src/app/defaults.json" for item in assessment.resources)


def test_pkgutil_get_data_rejects_dynamic_unsafe_and_namespace_only_resources(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "src/ns"
    namespace.mkdir(parents=True)
    (namespace / "defaults.json").write_text("{}\n", encoding="utf-8")
    (namespace / "main.py").write_text(
        "from pkgutil import get_data\n"
        "def main(name='defaults.json'):\n"
        "    get_data('ns', name)\n"
        "    get_data('ns', '../defaults.json')\n"
        "    return get_data('ns', 'C:\\\\outside.json')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='pkgutil-unsafe'\nversion='1.0'\n"
        "[project.scripts]\npkgutil-unsafe='ns.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert all(item.path != "src/ns/defaults.json" for item in assessment.resources)
    assert any(item.status == FindingStatus.NEEDS_VALIDATION for item in assessment.resources)


@pytest.mark.parametrize(
    ("imports", "files_call"),
    [
        ("import importlib.resources", "importlib.resources.files()"),
        ("import importlib.resources as ir", "ir.files()"),
        ("from importlib import resources", "resources.files()"),
        ("from importlib import resources as ir", "ir.files()"),
        ("from importlib.resources import files", "files()"),
        ("from importlib.resources import files as resource_files", "resource_files()"),
    ],
)
def test_importlib_resources_implicit_anchor_promotes_caller_resource(
    tmp_path: Path, imports: str, files_call: str
) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{"default": true}\n', encoding="utf-8")
    (package / "main.py").write_text(
        f"{imports}\n\ndef main():\n"
        f"    return {files_call}.joinpath('defaults.json').read_text(encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'implicit-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nimplicit-resource-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    resource = next(item for item in assessment.resources if item.path == "src/app/defaults.json")
    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert resource.packaging_status == "repository_adjacent"
    assert resource.path in staged


@pytest.mark.parametrize(
    ("source", "entry_point", "resource"),
    [
        ("src/app/__init__.py", "app:main", "src/app/defaults.json"),
        ("src/app/sub/__init__.py", "app.sub:main", "src/app/sub/defaults.json"),
        ("src/app/sub/module.py", "app.sub.module:main", "src/app/sub/defaults.json"),
        ("src/main.py", "main:main", "src/defaults.json"),
    ],
)
def test_importlib_resources_implicit_anchor_uses_source_parent(
    tmp_path: Path, source: str, entry_point: str, resource: str
) -> None:
    source_path = tmp_path / source
    source_path.parent.mkdir(parents=True)
    for parent in source_path.parents:
        if parent == tmp_path / "src":
            break
        init = parent / "__init__.py"
        if not init.exists() and parent != source_path.parent:
            init.write_text("", encoding="utf-8")
    (tmp_path / resource).write_text('{}\n', encoding="utf-8")
    source_path.write_text(
        "from importlib.resources import files\n\n"
        "def main():\n    return files().joinpath('defaults.json').read_bytes()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'caller-resource-app'\nversion = '1.0'\n"
        f"[project.scripts]\ncaller-resource-app = '{entry_point}'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    assert next(item for item in assessment.resources if item.path == resource).path == resource


def test_importlib_resources_implicit_anchor_honors_source_root_and_keywords(
    tmp_path: Path,
) -> None:
    package = tmp_path / "lib/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{}\n', encoding="utf-8")
    (package / "main.py").write_text(
        "from importlib.resources import files\n\n"
        "def main():\n"
        "    files().joinpath('defaults.json').read_text()\n"
        "    files(anchor='app').joinpath('defaults.json').read_text()\n"
        "    return files(package='app').joinpath('defaults.json').read_text()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'lib-implicit-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nlib-implicit-resource-app = 'app.main:main'\n"
        "[tool.setuptools]\npackages = ['app']\npackage-dir = {'' = 'lib'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    resource = next(item for item in assessment.resources if item.path == "lib/app/defaults.json")
    assert len(
        [
            evidence
            for evidence in resource.evidence
            if "importlib.resources.files" in evidence.detail
        ]
    ) == 2


def test_importlib_resources_rejects_unproven_or_escaping_resource_paths(tmp_path: Path) -> None:
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{}\n', encoding="utf-8")
    (package / "main.py").write_text(
        "from pathlib import Path\n"
        "def files(name):\n    return Path(name)\n"
        "def main(name='defaults.json'):\n"
        "    files('app').joinpath('defaults.json').read_text()\n"
        "    from importlib.resources import files as resource_files\n"
        "    return resource_files('app').joinpath('../secret.txt').read_text()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'unproven-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nunproven-resource-app = 'app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert all(item.path != "src/app/defaults.json" for item in assessment.resources)
    escaped = next(item for item in assessment.resources if "secret.txt" in item.path)
    assert escaped.status == FindingStatus.NEEDS_VALIDATION
    assert all("secret.txt" not in path for path in staged)


def test_dotted_import_promotion_includes_and_scans_regular_package_initializers(
    tmp_path: Path,
) -> None:
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/docs").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/main.py").write_text(
        "import docs.helper\n\ndef main(): return docs.helper.VALUE\n", encoding="utf-8"
    )
    (tmp_path / "src/docs/__init__.py").write_text(
        "REGISTERED = True\nimport docs.config\n", encoding="utf-8"
    )
    (tmp_path / "src/docs/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "src/docs/config.py").write_text("VALUE = 2\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='dotted-import-app'\nversion='1.0'\n"
        "[project.scripts]\ndotted-import-app='app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    staged = _staging_files(tmp_path, assessment, plan, include=True)
    inventory = {item.path: item for item in assessment.file_inventory}

    for path in ("src/docs/__init__.py", "src/docs/helper.py", "src/docs/config.py"):
        assert inventory[path].role == RepositoryFileRole.APPLICATION_SOURCE
        assert path in staged
    assert any(
        "docs.helper" in evidence.detail
        for evidence in inventory["src/docs/__init__.py"].evidence
    )


def test_dotted_import_promotion_preserves_existing_ancestor_initializers(tmp_path: Path) -> None:
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/pkg/sub").mkdir(parents=True)
    for relative in (
        "src/app/__init__.py",
        "src/pkg/__init__.py",
        "src/pkg/sub/__init__.py",
    ):
        (tmp_path / relative).write_text("", encoding="utf-8")
    (tmp_path / "src/app/main.py").write_text(
        "import pkg.sub.helper\n\ndef main(): return pkg.sub.helper.VALUE\n",
        encoding="utf-8",
    )
    (tmp_path / "src/pkg/sub/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='nested-import-app'\nversion='1.0'\n"
        "[project.scripts]\nnested-import-app='app.main:main'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    inventory = {item.path: item for item in assessment.file_inventory}

    for path in ("src/pkg/__init__.py", "src/pkg/sub/__init__.py", "src/pkg/sub/helper.py"):
        assert inventory[path].role == RepositoryFileRole.APPLICATION_SOURCE


def test_importlib_resources_uses_package_dir_parent_mapping(tmp_path: Path) -> None:
    package = tmp_path / "lib/sub"
    package.mkdir(parents=True)
    (tmp_path / "lib/__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "defaults.json").write_text('{}\n', encoding="utf-8")
    (tmp_path / "lib/main.py").write_text(
        "from importlib.resources import files\n"
        "def main():\n    return files('app.sub').joinpath('defaults.json').read_bytes()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'mapped-resource-app'\nversion = '1.0'\n"
        "[project.scripts]\nmapped-resource-app = 'app.main:main'\n"
        "[tool.setuptools]\npackages = ['app', 'app.sub']\npackage-dir = {app = 'lib'}\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))

    resource = next(item for item in assessment.resources if item.path == "lib/sub/defaults.json")
    assert resource.packaging_status == "repository_adjacent"


def test_wildcard_setuptools_package_data_uses_known_physical_package_mapping(
    tmp_path: Path,
) -> None:
    package = tmp_path / "code"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (package / "view.html").write_text("<p>runtime</p>\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'wildcard-data-app'\nversion = '1.0.0'\ndependencies = []\n"
        "[project.scripts]\nwildcard-data-app = 'app.main:main'\n"
        "[tool.setuptools]\npackages = ['app']\npackage-dir = {app = 'code'}\n"
        "[tool.setuptools.package-data]\n'*' = ['*.html']\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    source_plan = plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"

    resource = next(item for item in assessment.resources if item.path == "code/view.html")
    assert resource.packaging_status == "packaged"
    assert "code/view.html" in _staging_files(tmp_path, assessment, source_plan, include=True)


@pytest.mark.parametrize(
    ("namespaces", "expected"),
    [
        (True, {"example_app", "example_app.data", "example_app.namespace"}),
        (False, {"example_app"}),
    ],
)
def test_pyproject_find_discovers_packages_for_wildcard_package_data(
    tmp_path: Path, namespaces: bool, expected: set[str]
) -> None:
    app = tmp_path / "src/example_app"
    (app / "data").mkdir(parents=True)
    (app / "namespace").mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (app / "data/defaults.json").write_text("{}\n", encoding="utf-8")
    (app / "tests").mkdir()
    (app / "tests/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        f'''[project]
name = "discovered-data"
version = "1.0"
[tool.setuptools.packages.find]
where = ["src"]
include = ["example_app*"]
exclude = ["example_app.tests*"]
namespaces = {str(namespaces).lower()}
[tool.setuptools.package-data]
"*" = ["data/*.json"]
''',
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project
    members = resolve_package_data_members(tmp_path, project)

    assert set(project.packages) == expected
    assert [(item.source_path, item.installed_member_path) for item in members] == [
        ("src/example_app/data/defaults.json", "example_app/data/defaults.json")
    ]
    assert {
        (item.source_path, item.installed_member_path)
        for item in resolve_packaged_python_sources(tmp_path, project)
    } == {
        ("src/example_app/__init__.py", "example_app/__init__.py"),
        ("src/example_app/main.py", "example_app/main.py"),
    }


def test_setuptools_default_discovery_defines_python_and_wildcard_data_surface(
    tmp_path: Path,
) -> None:
    app = tmp_path / "src/example_app"
    (app / "data").mkdir(parents=True)
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text("from . import helpers\n", encoding="utf-8")
    (app / "helpers.py").write_text("VALUE = 1\n", encoding="utf-8")
    (app / "data/defaults.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "src/helper.py").write_text("VALUE = 3\n", encoding="utf-8")
    (tmp_path / "src/other_app").mkdir()
    (tmp_path / "src/other_app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/namespace_pkg/child").mkdir(parents=True)
    (tmp_path / "src/namespace_pkg/child/module.py").write_text("VALUE = 2\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "example-app"
version = "1.0"
[project.scripts]
example = "example_app.main:main"
[tool.setuptools.package-data]
"*" = ["data/*.json"]
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert {"example_app", "other_app", "namespace_pkg", "namespace_pkg.child"} <= set(
        project.packages
    )
    assert project.py_modules == ["helper"]
    assert {
        (item.source_path, item.installed_member_path)
        for item in resolve_packaged_python_sources(tmp_path, project)
    } >= {
        ("src/example_app/__init__.py", "example_app/__init__.py"),
        ("src/example_app/main.py", "example_app/main.py"),
        ("src/example_app/helpers.py", "example_app/helpers.py"),
        ("src/helper.py", "helper.py"),
    }
    assert [
        (item.source_path, item.installed_member_path)
        for item in resolve_package_data_members(tmp_path, project)
    ] == [("src/example_app/data/defaults.json", "example_app/data/defaults.json")]


def test_setuptools_default_flat_discovery_excludes_development_directories(tmp_path: Path) -> None:
    (tmp_path / "example_app").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs").mkdir()
    for directory in ("example_app", "tests", "docs"):
        (tmp_path / directory / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "example-app"
version = "1.0"
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert "example_app" in project.packages
    assert "tests" not in project.packages
    assert "docs" not in project.packages


@pytest.mark.parametrize(
    "reserved",
    [
        "ci",
        "bin",
        "debian",
        "doc",
        "docs",
        "manpages",
        "news",
        "newsfragments",
        "changelog",
        "test",
        "tests",
        "unit_test",
        "example",
        "examples",
        "tools",
        "scripts",
        "util",
        "utils",
        "tasks",
        "site_scons",
        "benchmark",
        "benchmarks",
        "documentation",
        "unit_tests",
        "requirements",
        "htmlcov",
        "python",
        "build",
        "dist",
        "venv",
        "env",
        "fabfile",
        "exercise",
        "exercises",
        "_private",
    ],
)
def test_setuptools_79_flat_package_defaults_exclude_reserved_names(
    tmp_path: Path, reserved: str
) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / reserved / "internal").mkdir(parents=True)
    for path in (
        tmp_path / "app/__init__.py",
        tmp_path / reserved / "__init__.py",
        tmp_path / reserved / "internal/__init__.py",
    ):
        path.write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'flat-defaults'\nversion = '1.0'\n",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == ["app"]


@pytest.mark.parametrize(
    "package", ["app", "my_tools", "mytools", "toolbox", "utilities", "benchmarking"]
)
def test_setuptools_79_flat_package_defaults_do_not_exclude_ordinary_names(
    tmp_path: Path, package: str
) -> None:
    (tmp_path / package).mkdir()
    (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'flat-ordinary'\nversion = '1.0'\n",
        encoding="utf-8",
    )

    assert inspect_metadata(tmp_path).project.packages == [package]


def test_setuptools_default_flat_single_module_defines_python_surface(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "flat-single-module"
version = "1.0"
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == []
    assert project.py_modules == ["helper"]


@pytest.mark.parametrize(
    "reserved",
    [
        "conftest",
        "test",
        "tests",
        "example",
        "examples",
        "build",
        "toxfile",
        "noxfile",
        "pavement",
        "dodo",
        "tasks",
        "fabfile",
        "SConstruct",
        "conanfile",
        "manage",
        "benchmark",
        "benchmarks",
        "exercise",
        "exercises",
        "_private",
    ],
)
def test_setuptools_79_flat_module_defaults_exclude_reserved_modules(
    tmp_path: Path, reserved: str
) -> None:
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / f"{reserved}.py").write_text("VALUE = 2\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'flat-modules'\nversion = '1.0'\n",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == []
    assert project.py_modules == ["helper"]


def test_setuptools_default_flat_package_surface_omits_loose_module(tmp_path: Path) -> None:
    (tmp_path / "example_app").mkdir()
    (tmp_path / "example_app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "flat-package-module"
version = "1.0"
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == ["example_app"]
    assert project.py_modules == []


def test_package_data_does_not_create_an_unselected_package_identity(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "ghost").mkdir()
    (tmp_path / "ghost/data.txt").write_text("not packaged\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'ghost-data'\nversion = '1.0'\n"
        "[tool.setuptools]\npy-modules = ['main']\n"
        "[tool.setuptools.package-data]\nghost = ['data.txt']\n",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == []
    assert project.py_modules == ["main"]
    assert resolve_package_data_members(tmp_path, project) == []


def test_package_data_applies_only_to_selected_packages(tmp_path: Path) -> None:
    for package in ("app", "ghost"):
        (tmp_path / package / "data").mkdir(parents=True)
        (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / package / "data/default.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\nbuild-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'selected-data'\nversion = '1.0'\n"
        "[tool.setuptools]\npackages = ['app']\n"
        "[tool.setuptools.package-data]\napp = ['data/*.json']\nghost = ['data/*.json']\n"
        "[tool.setuptools.exclude-package-data]\nghost = ['data/*.json']\n",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    resolved = resolve_package_data_members(tmp_path, project)

    assert [(item.source_path, item.installed_member_path) for item in resolved] == [
        ("app/data/default.json", "app/data/default.json")
    ]


def test_setuptools_default_flat_multi_package_surface_remains_unresolved(tmp_path: Path) -> None:
    for package in ("one", "two"):
        (tmp_path / package).mkdir()
        (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "flat-multi-package"
version = "1.0"
""",
        encoding="utf-8",
    )

    metadata = inspect_metadata(tmp_path)
    project = metadata.project

    assert project.packages == []
    assert project.py_modules == []
    assert metadata.setuptools_surface_unresolved
    assert not package_surface_resolved(project, tmp_path)


def test_setuptools_default_flat_multi_module_surface_remains_unresolved(tmp_path: Path) -> None:
    for module in ("one", "two"):
        (tmp_path / f"{module}.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "flat-multi-module"
version = "1.0"
""",
        encoding="utf-8",
    )

    metadata = inspect_metadata(tmp_path)
    project = metadata.project

    assert project.packages == []
    assert project.py_modules == []
    assert metadata.setuptools_surface_unresolved
    assert not package_surface_resolved(project, tmp_path)


@pytest.mark.parametrize(
    ("namespaces", "parent_initialized", "expected"),
    [
        (False, False, set()),
        (False, True, {"container", "container.sub"}),
        (True, False, {"container", "container.sub"}),
    ],
)
def test_setuptools_find_respects_non_namespace_ancestor_continuity(
    tmp_path: Path,
    namespaces: bool,
    parent_initialized: bool,
    expected: set[str],
) -> None:
    child = tmp_path / "src/container/sub"
    child.mkdir(parents=True)
    (child / "__init__.py").write_text("", encoding="utf-8")
    if parent_initialized:
        (tmp_path / "src/container/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        f'''[project]
name = "ancestor-continuity"
version = "1.0"
[tool.setuptools.packages.find]
where = ["src"]
namespaces = {str(namespaces).lower()}
''',
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert set(project.packages) == expected


def test_non_namespace_find_rejects_deep_descendant_below_missing_parent(tmp_path: Path) -> None:
    child = tmp_path / "src/container/intermediate/sub"
    child.mkdir(parents=True)
    (child / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/container/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "deep-ancestor-continuity"
version = "1.0"
[tool.setuptools.packages.find]
where = ["src"]
namespaces = false
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == ["container"]


def test_explicit_py_modules_prevents_default_package_auto_discovery(tmp_path: Path) -> None:
    (tmp_path / "src/example_app").mkdir(parents=True)
    (tmp_path / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "example-app"
version = "1.0"
[tool.setuptools]
py-modules = ["helper"]
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == []
    assert project.py_modules == ["helper"]


def test_package_data_exclusions_apply_after_safe_concrete_resolution(tmp_path: Path) -> None:
    for package in ("app", "other"):
        data = tmp_path / package / "data"
        data.mkdir(parents=True)
        (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
        (data / "defaults.json").write_text("{}\n", encoding="utf-8")
        (data / "private.json").write_text("{}\n", encoding="utf-8")
        (data / "temporary.tmp").write_text("temporary\n", encoding="utf-8")
        (data / ".hidden.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "excluded-data-app"
version = "1.0"
[tool.setuptools]
packages = ["app", "other"]
[tool.setuptools.package-data]
"*" = ["data/*.json", "data/*.tmp"]
app = ["data/*.json"]
[tool.setuptools.exclude-package-data]
app = ["data/private.json"]
"*" = ["data/*.tmp"]
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project
    members = resolve_package_data_members(tmp_path, project)
    paths = {member.source_path for member in members}

    assert project.exclude_package_data == {
        "app": ["data/private.json"],
        "*": ["data/*.tmp"],
    }
    assert paths == {
        "app/data/defaults.json",
        "other/data/defaults.json",
        "other/data/private.json",
    }
    assert all(member.evidence.file == "pyproject.toml" for member in members)


@pytest.mark.parametrize(
    ("source_root", "resource_path", "installed_path"),
    [
        ("", "app/data/default.json", "app/data/default.json"),
        ("src", "src/app/data/default.json", "app/data/default.json"),
    ],
)
def test_setup_cfg_package_data_is_authoritative_for_source_staging(
    tmp_path: Path, source_root: str, resource_path: str, installed_path: str
) -> None:
    package = tmp_path / source_root / "app"
    (package / "data").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(
        "import importlib.resources\n"
        "def main():\n"
        "    name = 'default' + '.json'\n"
        "    return importlib.resources.files('app').joinpath('data', name).read_text()\n",
        encoding="utf-8",
    )
    (package / "data/default.json").write_text('{"default": true}\n', encoding="utf-8")
    (package / "data/private.json").write_text('{"private": true}\n', encoding="utf-8")
    (tmp_path / source_root / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    package_dir = "\npackage_dir =\n    = src" if source_root else ""
    find_where = "\n[options.packages.find]\nwhere = src" if source_root else ""
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text(
        f"""[metadata]
name = setup-cfg-data
version = 1.0
[options]
packages = find:
py_modules =
    helper
python_requires = >=3.12{package_dir}
[options.entry_points]
console_scripts =
    setup-cfg-data = app.main:main
[options.package_data]
app =
    data/*.json
    templates/*.html
* =
    *.txt{find_where}
[options.exclude_package_data]
app =
    data/private.json
* =
    *.tmp
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    source_plan = plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"
    resource = next(item for item in assessment.resources if item.path == resource_path)
    inventory = next(item for item in assessment.file_inventory if item.path == resource_path)
    members = resolve_package_data_members(tmp_path, assessment.project)

    assert assessment.project.package_data == {
        "app": ["data/*.json", "templates/*.html"],
        "*": ["*.txt"],
    }
    assert assessment.project.exclude_package_data == {
        "app": ["data/private.json"],
        "*": ["*.tmp"],
    }
    assert assessment.project.packages == ["app"]
    assert assessment.project.py_modules == ["helper"]
    assert resource.packaging_status == "packaged"
    assert inventory.role == RepositoryFileRole.RUNTIME_RESOURCE
    staged = _staging_files(tmp_path, assessment, source_plan, include=True)
    assert resource_path in staged
    assert resource_path.replace("default.json", "private.json") not in staged
    assert [(member.source_path, member.installed_member_path) for member in members] == [
        (resource_path, installed_path)
    ]
    assert all("private.json" not in member.source_path for member in members)
    assert all(member.evidence.file == "setup.cfg" for member in members)


def test_setup_cfg_find_uses_global_package_dir_and_filters(tmp_path: Path) -> None:
    (tmp_path / "src/app/tests").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "src/app/tests/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        """[metadata]
Name = setup-discovered
Version = 1.0
[options]
packages = find:
package_dir =
    = src
[options.packages.find]
include =
    app*
exclude =
    app.tests*
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert project.packages == ["app"]
    assert project.source_roots == ["src"]
    assert {
        (item.source_path, item.installed_member_path)
        for item in resolve_packaged_python_sources(tmp_path, project)
    } == {
        ("src/app/__init__.py", "app/__init__.py"),
        ("src/app/module.py", "app/module.py"),
    }


@pytest.mark.parametrize(
    ("finder", "expected"),
    [("find:", set()), ("find_namespace:", {"container", "container.sub"})],
)
def test_setup_cfg_finder_preserves_its_namespace_policy(
    tmp_path: Path, finder: str, expected: set[str]
) -> None:
    child = tmp_path / "src/container/sub"
    child.mkdir(parents=True)
    (child / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        f"""[metadata]
name = setup-finder-policy
version = 1.0
[options]
packages = {finder}
package_dir =
    = src
""",
        encoding="utf-8",
    )

    project = inspect_metadata(tmp_path).project

    assert set(project.packages) == expected


def test_literal_setup_py_package_data_and_exclusions_share_the_resolver(tmp_path: Path) -> None:
    data = tmp_path / "app" / "data"
    data.mkdir(parents=True)
    (tmp_path / "app/__init__.py").write_text("", encoding="utf-8")
    (data / "defaults.json").write_text("{}\n", encoding="utf-8")
    (data / "private.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        """from setuptools import setup
setup(
    name="literal-data",
    version="1.0",
    packages=["app"],
    py_modules=["helper"],
    package_data={"": ["data/*.json"]},
    exclude_package_data={"": ["data/private.json"]},
)
""",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")

    project = inspect_metadata(tmp_path).project

    assert project.package_data == {"*": ["data/*.json"]}
    assert project.exclude_package_data == {"*": ["data/private.json"]}
    assert project.py_modules == ["helper"]
    assert [
        (member.source_path, member.installed_member_path, member.evidence.file)
        for member in resolve_package_data_members(tmp_path, project)
    ] == [("app/data/defaults.json", "app/data/defaults.json", "setup.py")]
    assert [
        (item.source_path, item.installed_member_path)
        for item in resolve_packaged_python_sources(tmp_path, project)
    ] == [
        ("app/__init__.py", "app/__init__.py"),
        ("helper.py", "helper.py"),
    ]


def test_setup_cfg_standard_options_are_case_insensitive_and_package_data_is_not(
    tmp_path: Path,
) -> None:
    package = tmp_path / "MyPackage"
    (package / "Assets").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (package / "Assets/default.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text(
        """[metadata]
Name = Example-App
Version = 1.2.3
[options]
Packages = find:
Python_Requires = >=3.12
Install_Requires =
    requests>=2
[options.entry_points]
console_scripts =
    MyTool = MyPackage.main:main
[options.package_data]
MyPackage =
    Assets/*.json
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    metadata = inspect_metadata(tmp_path)
    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    source_plan = plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"

    assert metadata.project.distribution_name == "Example-App"
    assert metadata.project.version == "1.2.3"
    assert metadata.python.requires_python == ">=3.12"
    assert [
        (item.distribution_name, item.declared_constraint) for item in metadata.dependencies
    ] == [("requests", ">=2")]
    assert [
        (item.name, item.target, item.declared_group)
        for item in metadata.project.entry_points
    ] == [("MyTool", "MyPackage.main:main", "console_scripts")]
    assert metadata.project.package_data == {"MyPackage": ["Assets/*.json"]}
    assert [
        (member.source_path, member.installed_member_path)
        for member in resolve_package_data_members(tmp_path, metadata.project)
    ] == [("MyPackage/Assets/default.json", "MyPackage/Assets/default.json")]
    assert "MyPackage/Assets/default.json" in _staging_files(
        tmp_path, assessment, source_plan, include=True
    )


@pytest.mark.parametrize(
    ("conflict", "expected_role"),
    [
        ("ignored", RepositoryFileRole.IGNORED_OR_LOCAL),
        ("mutable", RepositoryFileRole.MUTABLE_STATE_CANDIDATE),
    ],
)
def test_non_git_authoritative_package_data_conflicts_block_source_staging(
    tmp_path: Path, conflict: str, expected_role: RepositoryFileRole
) -> None:
    package = tmp_path / "app"
    (package / "data").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    main = (
        "from pathlib import Path\n"
        "def main():\n"
        "    return Path(__file__).with_name('data').joinpath('default.json').read_text()\n"
    )
    if conflict == "mutable":
        main = main.replace("read_text()", "write_text('local state')")
    (package / "main.py").write_text(main, encoding="utf-8")
    (package / "data/default.json").write_text('{"default": true}\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "non-git-package-data"
version = "1.0"
[project.scripts]
non-git-package-data = "app.main:main"
[tool.setuptools]
packages = ["app"]
[tool.setuptools.package-data]
app = ["data/*.json"]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    if conflict == "ignored":
        (tmp_path / ".gitignore").write_text("app/data/default.json\n", encoding="utf-8")

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)
    inventory = next(
        item for item in assessment.file_inventory if item.path == "app/data/default.json"
    )

    assert inventory.role == expected_role
    with pytest.raises(PreparationError, match="cannot be silently omitted"):
        _staging_files(tmp_path, assessment, plan, include=True)


@pytest.mark.parametrize(
    ("package", "package_directories", "source_roots", "physical_root"),
    [
        ("app", {"app": "code"}, [], "code"),
        ("app.sub", {"app": "lib"}, [], "lib/sub"),
        ("app.sub.deep", {"app": "lib"}, [], "lib/sub/deep"),
        ("app.sub.deep", {"app": "lib", "app.sub": "special"}, [], "special/deep"),
        ("app.sub", {"": "src"}, [], "src/app/sub"),
        ("app", {}, ["."], "app"),
    ],
)
def test_package_data_resolver_uses_longest_parent_package_dir_mapping(
    tmp_path: Path,
    package: str,
    package_directories: dict[str, str],
    source_roots: list[str],
    physical_root: str,
) -> None:
    resource = tmp_path / physical_root / "data/default.json"
    resource.parent.mkdir(parents=True)
    resource.write_text("{}\n", encoding="utf-8")
    project = PackagingAssessment(
        packages=[package],
        package_directories=package_directories,
        source_roots=source_roots,
        package_data={package: ["data/*.json"]},
    )

    resolved = resolve_package_data_members(tmp_path, project)

    assert [(item.source_path, item.installed_member_path) for item in resolved] == [
        (f"{physical_root}/data/default.json", f"{package.replace('.', '/')}/data/default.json")
    ]


def test_installed_namespace_package_data_and_user_local_wrapper_select_package_mode(
    tmp_path: Path,
) -> None:
    (tmp_path / "code").mkdir()
    (tmp_path / "code/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "code/view.html").write_text("<html></html>\n", encoding="utf-8")
    (tmp_path / "code/main.py").write_text(
        """from pathlib import Path
VIEW = Path(__file__).with_name("view.html")
def user_data_path(name):
    return Path.home() / ".sample" / name
def oauth_path():
    return user_data_path("oauth.json")
def save():
    cache_path = oauth_path()
    cache_path.write_text("state")
def main():
    return VIEW.read_text()
""",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"
[project]
name = "mapped-app"
version = "1.2.3"
requires-python = ">=3.12"
dependencies = []
[project.gui-scripts]
mapped-app = "installed_app.main:main"
[tool.setuptools]
packages = ["installed_app"]
package-dir = {installed_app = "code"}
[tool.setuptools.package-data]
installed_app = ["view.html"]
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment)

    view = next(item for item in assessment.resources if item.path == "code/view.html")
    oauth = next(
        item for item in assessment.write_locations if "oauth_path" in item.path_expression
    )
    assert view.packaging_status == "packaged"
    assert oauth.classification == "user_local"
    assert plan.deployment_mode == "package"
    assert plan.deployment_mode_condition == "ENTRYPOINT_REQUIRES_PACKAGE_MODE"
    assert plan.readiness.state == "BLOCKED_PENDING_APPLICATION_WHEEL"
    assert plan.entry_point.target == "installed_app.main:main"

    view.packaging_status = "repository_adjacent"
    conflict = create_deployment_plan(assessment)
    assert conflict.deployment_mode_condition == "DEPLOYMENT_MODE_CONFLICT"
    assert conflict.readiness.state == "BLOCKED"
    assert "DEPLOYMENT_MODE_CONFLICT" in conflict.readiness.blocker_codes


def test_unique_write_path_wrapper_infers_user_local(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
def oauth_path():
    return user_data_path("oauth.json")
oauth = oauth_path()
oauth.write_text("state")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    oauth = next(
        item for item in assessment.write_locations if "oauth_path" in item.path_expression
    )

    assert oauth.classification == "user_local"


def test_same_class_self_method_wrapper_infers_user_local(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
class Paths:
    def oauth_path(self):
        return user_data_path("oauth.json")
    def save(self):
        oauth = self.oauth_path()
        oauth.write_text("state")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    oauth = next(
        item for item in assessment.write_locations if "oauth_path" in item.path_expression
    )

    assert oauth.classification == "user_local"


def test_same_class_cls_method_wrapper_infers_user_local(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
class Paths:
    @classmethod
    def oauth_path(cls):
        return user_data_path("oauth.json")
    @classmethod
    def save(cls):
        oauth = cls.oauth_path()
        oauth.write_text("state")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    oauth = next(
        item for item in assessment.write_locations if "oauth_path" in item.path_expression
    )

    assert oauth.classification == "user_local"


@pytest.mark.parametrize(
    ("method_return", "incorrect_classification"),
    [
        ('user_data_path("state.json")', "user_local"),
        ('Path(__file__).with_name("state.json")', "project_local"),
    ],
)
def test_unrelated_attribute_call_does_not_borrow_local_method_summary(
    tmp_path: Path,
    method_return: str,
    incorrect_classification: str,
) -> None:
    (tmp_path / "app.py").write_text(
        f"""from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
class LocalPaths:
    def cache_path(self):
        return {method_return}
external = SomeImportedClient()
state = external.cache_path()
state.write_text("value")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    state = next(
        item for item in assessment.write_locations if "cache_path" in item.path_expression
    )

    assert state.classification != incorrect_classification
    assert state.classification == "unknown"
    assert state.status == FindingStatus.NEEDS_VALIDATION


def test_nested_function_return_does_not_summarize_outer_wrapper(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
def outer():
    def inner():
        return user_data_path("state.json")
    do_something()
state = outer()
state.write_text("value")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    state = next(
        item for item in assessment.write_locations if "outer" in item.path_expression
    )

    assert state.classification == "unknown"
    assert state.status == FindingStatus.NEEDS_VALIDATION


def test_duplicate_method_names_do_not_share_return_summary(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """from pathlib import Path
def user_data_path(name):
    return Path.home() / ".sample" / name
class A:
    def cache_path(self):
        return user_data_path("state.json")
class B:
    def cache_path(self):
        return Path(__file__).with_name("state.json")
a_state = A().cache_path()
b_state = B().cache_path()
a_state.write_text("a")
b_state.write_text("b")
""",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))
    cache_writes = [
        item for item in assessment.write_locations if "cache_path" in item.path_expression
    ]

    assert len(cache_writes) == 2
    assert all(item.classification == "unknown" for item in cache_writes)
    assert all(item.status == FindingStatus.NEEDS_VALIDATION for item in cache_writes)


def test_cache_collision_directories_are_inventory_local_state(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    cache = tmp_path / "app" / "__pycache__ (12)"
    cache.mkdir(parents=True)
    (cache / "module.cpython-312.pyc").write_bytes(b"cache")

    assessment = assess_repository(_repository(tmp_path))
    cache_items = [item for item in assessment.file_inventory if "__pycache__" in item.path]

    assert cache_items
    assert all(item.role == RepositoryFileRole.IGNORED_OR_LOCAL for item in cache_items)
    assert all(not item.included_in_runtime_scan for item in cache_items)


def test_materialized_archive_uses_role_aware_staging_without_git(tmp_path: Path) -> None:
    _write_fingerprint_app(tmp_path)
    repository = MaterializedRepository(
        root=tmp_path,
        source="https://github.com/example/materialized/archive",
        source_kind="github_archive",
    )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=tmp_path)

    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert "app.py" in staged
    assert "assets/view.html" in staged
    assert "docs/snippet.py" not in staged
    assert "deployment/helper.py" not in staged


def test_conventional_resource_directory_stages_descendants_not_similar_prefixes(
    tmp_path: Path,
) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets2").mkdir()
    (tmp_path / "assets/view.html").write_text("runtime\n", encoding="utf-8")
    (tmp_path / "assets/templates").mkdir()
    (tmp_path / "assets/templates/page.html").write_text("nested\n", encoding="utf-8")
    (tmp_path / "assets2/view.html").write_text("unrelated\n", encoding="utf-8")
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "conventional-assets"
version = "1.0"
[project.scripts]
conventional-assets = "app.main:main"
[tool.setuptools.packages.find]
where = ["src"]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    assessment = assess_repository(_repository(tmp_path))
    plan = create_deployment_plan(assessment, repository_root=tmp_path)

    staged = _staging_files(tmp_path, assessment, plan, include=True)

    assert plan.deployment_mode == "source"
    assert {"assets/view.html", "assets/templates/page.html"} <= staged.keys()
    assert "assets2/view.html" not in staged


def test_pathspec_is_declared_as_a_runtime_dependency() -> None:
    root = Path(__file__).parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    import pathspec

    assert "pathspec>=0.12,<1" in pyproject
    assert pathspec.PathSpec is not None


def test_all_structural_guidance_is_evidence_backed_and_noncontradictory(
    tmp_path: Path,
) -> None:
    _write_fingerprint_app(tmp_path)
    guidance = assess_repository(_repository(tmp_path)).structural_guidance
    by_code: dict[str, set[str]] = {}

    for item in guidance:
        assert item.evidence, item.code
        by_code.setdefault(item.code, set()).add(item.classification.value)

    assert all(len(classifications) == 1 for classifications in by_code.values())


def test_generic_vendor_runtime_evidence_does_not_require_arcgis_terms(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import tkinter\n", encoding="utf-8")
    (tmp_path / "deployment").mkdir()
    (tmp_path / "deployment/setup.py").write_text(
        "import winreg\n# discover vendor registry and clone vendor Python environment\n",
        encoding="utf-8",
    )

    assessment = assess_repository(_repository(tmp_path))

    assert [item.name for item in assessment.vendor_runtimes] == [
        "Vendor-managed Python runtime"
    ]
    assert not any("ArcGIS" in item.title for item in assessment.structural_guidance)
