from pathlib import Path

from python_deployment_builder.cli import application_id, main

FIXTURES = Path(__file__).parent / "fixtures"


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
