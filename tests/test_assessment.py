import subprocess
from pathlib import Path

from python_deployment_builder.analysis.assessor import _git_revision, assess_repository
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


def _git(path: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _committed_repository(root: Path, *, name: str = "revision-test") -> str:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "1.0.0"\n', encoding="utf-8"
    )
    _git(root.parent, "init", "-q", str(root))
    _git(root, "config", "user.name", "PDB Test")
    _git(root, "config", "user.email", "pdb@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")
    return _git(root, "rev-parse", "HEAD")


def test_git_revision_uses_selected_repository_git_identity(tmp_path: Path) -> None:
    normal = tmp_path / "normal"
    normal_head = _committed_repository(normal)
    assert _git_revision(normal) == normal_head

    nested = normal / "projects" / "nested"
    nested.mkdir(parents=True)
    assert _git_revision(nested) == normal_head

    child = tmp_path / "child"
    child_head = _committed_repository(child, name="child")
    superproject = tmp_path / "superproject"
    _committed_repository(superproject, name="superproject")
    _git(
        superproject,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        str(child),
        "app-submodule",
    )
    _git(superproject, "commit", "-qm", "add submodule")
    assert _git(superproject, "rev-parse", "HEAD") != child_head
    assert (superproject / "app-submodule/.git").is_file()
    assert _git_revision(superproject / "app-submodule") == child_head

    linked = tmp_path / "linked-worktree"
    _git(normal, "worktree", "add", "-q", "-b", "linked", str(linked))
    assert (linked / ".git").is_file()
    linked_head = _git(linked, "rev-parse", "HEAD")
    assert _git_revision(linked) == linked_head
    _git(linked, "checkout", "--detach", "-q")
    assert _git_revision(linked) == linked_head
    assert _git_revision(tmp_path / "not-git") is None


def test_assessment_revision_agrees_with_generation_git_identity(tmp_path: Path) -> None:
    root = tmp_path / "revision-project"
    head = _committed_repository(root)
    repository = MaterializedRepository(root=root, source=str(root), source_kind="local")

    assert assess_repository(repository).repository.revision == head
