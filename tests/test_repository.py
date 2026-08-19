import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.repository import (
    RepositoryLoadError,
    parse_public_github_url,
    safe_extract_zip,
)


def test_public_github_url_parser() -> None:
    assert parse_public_github_url("https://github.com/alwunder/example.git") == (
        "alwunder",
        "example",
    )
    assert parse_public_github_url("https://example.com/alwunder/example") is None
    assert parse_public_github_url("https://github.com/alwunder/example/issues") is None
    assert parse_public_github_url("https://github.com/alwunder/example?token=secret") is None


def test_safe_zip_extraction_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("repository/good.txt", "good")
        bundle.writestr("../escaped.txt", "bad")

    with pytest.raises(RepositoryLoadError, match="Unsafe archive"):
        safe_extract_zip(archive, tmp_path / "output")
    assert not (tmp_path / "escaped.txt").exists()


def test_safe_zip_extraction_returns_single_root(tmp_path: Path) -> None:
    archive = tmp_path / "good.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("owner-repo-sha/pyproject.toml", "[project]\nname='demo'\n")

    root = safe_extract_zip(archive, tmp_path / "output")
    assert root.name == "owner-repo-sha"
    assert (root / "pyproject.toml").is_file()
