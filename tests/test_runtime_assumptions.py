from pathlib import Path

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
