from pathlib import Path

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.models import SuitabilityRating
from python_deployment_builder.reporting.markdown import render_assessment_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _assess(name: str):
    root = FIXTURES / name
    return assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )


def test_target_fixture_assessment_is_yellow_and_explains_source_risks() -> None:
    assessment = _assess("target_app")
    codes = {risk.code for risk in assessment.risks}

    assert assessment.rating == SuitabilityRating.YELLOW
    assert "DEPENDENCY_LOCK_MISSING" in codes
    assert "REPOSITORY_ADJACENT_RESOURCES" in codes
    assert "PROJECT_LOCAL_WRITES" in codes
    assert "SECRET_CONFIGURATION" in codes
    assert "NATIVE_WHEELS_UNVERIFIED" in codes
    assert not [
        item
        for item in assessment.imports
        if item.classification == "observed_undeclared_third_party"
    ]


def test_program_files_fixture_is_red() -> None:
    assessment = _assess("bad_program_files_write")
    assert assessment.rating == SuitabilityRating.RED


def test_markdown_contains_human_readable_sections() -> None:
    rendered = render_assessment_markdown(_assess("target_app"))
    assert "# Static deployment assessment" in rendered
    assert "## Runtime assumptions" in rendered
    assert "OPENAI_API_KEY" in rendered
    assert "REPOSITORY_ADJACENT_RESOURCES" in rendered
