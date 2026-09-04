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
