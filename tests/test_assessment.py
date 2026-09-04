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
    assert "Declared group" in rendered
    assert "## Runtime assumptions" in rendered
    assert "OPENAI_API_KEY" in rendered
    assert "REPOSITORY_ADJACENT_RESOURCES" in rendered


def test_git_revision_requires_a_full_hex_object_id(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "revision-test"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    ref = git / "refs" / "heads" / "main"
    ref.write_text("a" * 40 + "\n", encoding="ascii")
    repository = MaterializedRepository(root=tmp_path, source=str(tmp_path), source_kind="local")
    assert assess_repository(repository).repository.revision == "a" * 40

    ref.write_text("not-a-commit\n", encoding="ascii")
    assert assess_repository(repository).repository.revision is None
