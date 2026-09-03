from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.imports import scan_imports
from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.cli import main
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import _staging_files, generate_deployment_kit
from python_deployment_builder.models import (
    FindingStatus,
    OnlineCompatibilityAssessment,
    OnlineIndexContext,
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
