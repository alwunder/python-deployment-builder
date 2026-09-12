from pathlib import Path

import pytest

from python_deployment_builder.analysis.runtime_assumptions import scan_runtime_assumptions

FIXTURES = Path(__file__).parent / "fixtures"


def test_environment_gui_paths_and_writes_are_detected() -> None:
    result = scan_runtime_assumptions(FIXTURES / "target_app", ["src"])

    assert any(item.name == "Tkinter" for item in result.runtime_requirements)
    assert any("__file__" in item.name for item in result.runtime_requirements)
    key = next(item for item in result.configuration_requirements if item.name == "OPENAI_API_KEY")
    assert key.secret is True
    assert any(item.classification == "project_local" for item in result.write_locations)
    assert any("output_dir" in item.path_expression for item in result.write_locations)


def test_external_executable_is_detected() -> None:
    result = scan_runtime_assumptions(FIXTURES / "external_executable", ["."])
    assert any(item.name == "convert.exe" for item in result.runtime_requirements)


@pytest.mark.parametrize(
    ("call", "name"),
    [
        ("os.getenv('X')", "X"),
        ("os.getenv(key='X')", "X"),
        ("os.getenv('X', 'fallback')", "X"),
        ("os.getenv(key='X', default='fallback')", "X"),
        ("os.environ.get('X')", "X"),
        ("os.environ.get(key='X')", "X"),
        ("os.environ.get('X', 'fallback')", "X"),
        ("os.environ.get(key='X', default='fallback')", "X"),
        ("os.environ['X']", "X"),
        ("os.environ.get(key='API-KEY')", "API-KEY"),
    ],
)
def test_environment_reads_accept_literal_positional_and_keyword_keys(
    tmp_path: Path, call: str, name: str
) -> None:
    (tmp_path / "app.py").write_text(f"import os\nVALUE = {call}\n", encoding="utf-8")

    result = scan_runtime_assumptions(tmp_path, ["."])

    requirement = next(item for item in result.configuration_requirements if item.name == name)
    assert requirement.secret is False


def test_environment_keyword_key_stays_literal_only_and_positional_wins_duplicates(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nname = 'DYNAMIC'\n"
        "first = os.getenv(key=name)\n"
        "second = os.getenv('POSITIONAL', key='KEYWORD')\n",
        encoding="utf-8",
    )

    result = scan_runtime_assumptions(tmp_path, ["."])

    assert {item.name for item in result.configuration_requirements} == {"POSITIONAL"}
