from pathlib import Path

from python_deployment_builder.analysis.imports import scan_imports
from python_deployment_builder.analysis.metadata import inspect_metadata

FIXTURES = Path(__file__).parent / "fixtures"


def test_ast_import_classification_and_distribution_mapping() -> None:
    root = FIXTURES / "target_app"
    metadata = inspect_metadata(root)
    result = scan_imports(root, metadata.project.source_roots, metadata.dependencies)
    by_name = {(item.import_name, item.classification): item for item in result.observations}

    assert ("tkinter", "standard_library") in by_name
    assert ("target_app", "local_project") not in by_name  # no self-import in fixture
    assert by_name[("PIL", "declared_third_party")].distribution_name == "Pillow"
    assert by_name[("yaml", "declared_third_party")].distribution_name == "PyYAML"
    assert by_name[("tksheet", "declared_third_party")].optional_import is True
    assert result.parse_errors == []


def test_unmatched_import_is_reported_not_executed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import mystery_package\n", encoding="utf-8")
    result = scan_imports(tmp_path, ["."], [])

    assert result.observations[0].classification == "observed_undeclared_third_party"
