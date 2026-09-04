import stat
import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.repository import (
    RepositoryLoadError,
    materialize_git_head_snapshot,
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


def test_git_head_materialization_skips_links_without_weakening_external_zip_safety(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "head.zip"
    link = zipfile.ZipInfo("docs/unrelated-link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("app.py", "def main(): return 0\n")
        bundle.writestr(link, "../../outside")

    with pytest.raises(RepositoryLoadError, match="symbolic links are not allowed"):
        safe_extract_zip(archive, tmp_path / "external-output")

    destination = tmp_path / "head-output"
    skipped = materialize_git_head_snapshot(archive, destination)

    assert skipped == {"docs/unrelated-link"}
    assert (destination / "app.py").is_file()
    assert not (destination / "docs/unrelated-link").exists()
