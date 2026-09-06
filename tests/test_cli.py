import subprocess
from pathlib import Path

import pytest

from python_deployment_builder.cli import application_id, build_parser, main

FIXTURES = Path(__file__).parent / "fixtures"


def _assert_all_reports(output: Path) -> None:
    reports = output / "reports"
    assert (reports / "assessment.json").is_file()
    assert (reports / "assessment.md").is_file()
    assert (reports / "deployment-plan.json").is_file()
    assert (reports / "deployment-plan.md").is_file()


def _write_all_source(root: Path, *, package_mode: bool = False, lock: bool = True) -> None:
    package = root / ("code" if package_mode else "app")
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("def main(): return 0\n", encoding="utf-8")
    mapping = (
        "[tool.setuptools]\npackages = ['installed_app']\n"
        "package-dir = {installed_app = 'code'}\n"
        if package_mode
        else "[tool.setuptools]\npackages = ['app']\n"
    )
    target = "installed_app.main:main" if package_mode else "app.main:main"
    (root / "pyproject.toml").write_text(
        "[project]\nname='all-report-app'\nversion='1.0'\ndependencies=[]\n"
        f"[project.scripts]\nall-report-app='{target}'\n" + mapping,
        encoding="utf-8",
    )
    if lock:
        (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")


def test_safe_application_id() -> None:
    assert application_id("Geo Map Explanation Extractor") == "geo-map-explanation-extractor"
    assert application_id("../../") == "python-application"


def test_assess_command_writes_both_reports(tmp_path: Path) -> None:
    result = main(
        [
            "assess",
            str(FIXTURES / "target_app"),
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert result == 0
    assert (tmp_path / "assessment.json").is_file()
    assert (tmp_path / "assessment.md").is_file()


def test_plan_command_writes_both_reports_without_online_mutation(tmp_path: Path) -> None:
    result = main(
        [
            "plan",
            str(FIXTURES / "target_app"),
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert result == 1
    assert (tmp_path / "deployment-plan.json").is_file()
    assert (tmp_path / "deployment-plan.md").is_file()


def test_plan_parser_accepts_repeatable_extras() -> None:
    arguments = build_parser().parse_args(
        ["plan", "repository", "--extra", "map", "--extra", "feature-two"]
    )

    assert arguments.extra == ["map", "feature-two"]


@pytest.mark.parametrize("case", ["missing-entry", "missing-lock", "missing-wheel"])
def test_all_persists_assessment_and_plan_reports_before_readiness_returns(
    tmp_path: Path, case: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    if case == "missing-entry":
        (source / "pyproject.toml").write_text(
            "[project]\nname='no-entry'\nversion='1.0'\ndependencies=[]\n",
            encoding="utf-8",
        )
        (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    else:
        _write_all_source(source, package_mode=case == "missing-wheel", lock=case != "missing-lock")
    output = tmp_path / "output"

    result = main(["all", str(source), "--output-dir", str(output)])

    assert result == 2
    _assert_all_reports(output)
    assert not (output / "deployment-kit").exists()
    assert not (output / "distribution").exists()


def test_all_persists_reports_when_reviewed_dependency_artifact_is_missing(tmp_path: Path) -> None:
    output = tmp_path / "output"

    result = main(
        [
            "all",
            str(FIXTURES / "optional_map_app"),
            "--extra",
            "map",
            "--output-dir",
            str(output),
        ]
    )

    assert result == 2
    _assert_all_reports(output)
    assert not (output / "deployment-kit").exists()


def test_all_persists_reports_when_risk_gate_blocks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_all_source(source)
    (source / "app/main.py").write_text(
        "from pathlib import Path\n"
        "Path('C:\\\\Program Files\\\\Unsafe\\\\state.json').write_text('state')\n"
        "def main(): return 0\n",
        encoding="utf-8",
    )
    output = tmp_path / "output"

    result = main(["all", str(source), "--output-dir", str(output)])

    assert result == 2
    _assert_all_reports(output)
    assert not (output / "deployment-kit").exists()


def test_uv_workspace_assess_plan_and_all_report_a_typed_blocker(tmp_path: Path) -> None:
    """A workspace is diagnosable, but M6.1 must not stage a partial workspace."""

    source = tmp_path / "workspace-root"
    source.mkdir()
    _write_all_source(source)
    (source / "packages/unrelated/src/unrelated").mkdir(parents=True)
    (source / "packages/unrelated/pyproject.toml").write_text(
        "[project]\nname='unrelated'\nversion='1.0'\n", encoding="utf-8"
    )
    (source / "packages/unrelated/src/unrelated/__init__.py").write_text(
        "", encoding="utf-8"
    )
    with (source / "pyproject.toml").open("a", encoding="utf-8") as handle:
        handle.write("\n[tool.uv.workspace]\nmembers=['packages/*']\nexclude=['packages/none']\n")

    assess_output = tmp_path / "assess"
    plan_output = tmp_path / "plan"
    all_output = tmp_path / "all"
    assert main(["assess", str(source), "--output-dir", str(assess_output)]) == 0
    assert main(["plan", str(source), "--output-dir", str(plan_output)]) == 1
    assert main(["all", str(source), "--output-dir", str(all_output)]) == 2

    assert "UV_WORKSPACE_UNSUPPORTED" in (assess_output / "assessment.json").read_text(
        encoding="utf-8"
    )
    assert "UV_WORKSPACE_UNSUPPORTED" in (plan_output / "deployment-plan.json").read_text(
        encoding="utf-8"
    )
    _assert_all_reports(all_output)
    assert "UV_WORKSPACE_UNSUPPORTED" in (all_output / "reports/deployment-plan.json").read_text(
        encoding="utf-8"
    )
    assert not (all_output / "deployment-kit").exists()


def test_sparse_worktree_assess_plan_and_all_persist_blocker_reports(tmp_path: Path) -> None:
    source = tmp_path / "sparse-source"
    source.mkdir()
    _write_all_source(source)
    (source / "lazy helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "update-index",
            "--skip-worktree",
            "--",
            "lazy helper.py",
        ],
        check=True,
    )
    (source / "lazy helper.py").unlink()

    assess_output = tmp_path / "assess"
    plan_output = tmp_path / "plan"
    all_output = tmp_path / "all"
    assert main(["assess", str(source), "--output-dir", str(assess_output)]) == 0
    assert main(["plan", str(source), "--output-dir", str(plan_output)]) == 1
    assert main(["all", str(source), "--output-dir", str(all_output)]) == 2

    for report in (
        assess_output / "assessment.json",
        plan_output / "deployment-plan.json",
        all_output / "reports/deployment-plan.json",
    ):
        assert "SPARSE_WORKTREE_UNSUPPORTED" in report.read_text(encoding="utf-8")
    assert not (all_output / "deployment-kit").exists()
