from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.cli import build_parser
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.packaging import package_deployment_kit, safe_extract_zip
from python_deployment_builder.packaging.archive import (
    FIXED_ZIP_TIMESTAMP,
    ArchiveSafetyError,
)
from python_deployment_builder.packaging.packager import PackageError, safe_application_slug
from python_deployment_builder.validation import validate_static_kit

FIXTURES = Path(__file__).parent / "fixtures"


def _repository(name: str) -> MaterializedRepository:
    root = FIXTURES / name
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def _make_wheel(path: Path) -> Path:
    wheel = path / "proxy_tools-0.1.0-py3-none-any.whl"
    dist_info = "proxy_tools-0.1.0.dist-info"
    files = {
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\nName: proxy-tools\nVersion: 0.1.0\n\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "proxy_tools/__init__.py": "",
    }
    record_name = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for filename, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data.encode()).digest()).rstrip(b"=")
        writer.writerow((filename, f"sha256={digest.decode()}", str(len(data.encode()))))
    writer.writerow((record_name, "", ""))
    files[record_name] = output.getvalue()
    with zipfile.ZipFile(wheel, "w") as bundle:
        for filename, data in files.items():
            bundle.writestr(filename, data)
    return wheel


def _generate_kit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    fixture: str = "prepared_gui",
    extras: list[str] | None = None,
    artifact: Path | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fake_uv = tmp_path / "developer-uv.exe"
    fake_uv.write_bytes(b"verified uv 0.12.5")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / f"{fixture}-kit"
    generate_deployment_kit(
        _repository(fixture),
        kit,
        selected_extras=extras or [],
        artifact_values=[f"proxy-tools={artifact}"] if artifact else [],
    )
    return kit


def _update_index_hash(kit: Path, relative: str) -> None:
    index_path = kit / "deployment" / "generated-files.json"
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256((kit / relative).read_bytes()).hexdigest()
    for item in payload["files"]:
        if item["path"] == relative:
            item["sha256"] = digest
            break
    else:
        raise AssertionError(f"{relative} is not indexed")
    index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, int, str | None]]:
    snapshot = {}
    for path in sorted(root.rglob("*")):
        stat_result = path.stat()
        snapshot[path.relative_to(root).as_posix()] = (
            "file" if path.is_file() else "directory",
            stat_result.st_size,
            stat_result.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
    return snapshot


def test_package_cli_parses_options() -> None:
    arguments = build_parser().parse_args(
        ["package", "kit", "--output-dir", "dist", "--version", "1.2.3", "--dry-run"]
    )
    assert arguments.command == "package"
    assert arguments.version == "1.2.3"
    assert arguments.dry_run


def test_deterministic_package_checksum_and_no_wrapper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    first = package_deployment_kit(kit, output_directory=tmp_path / "dist-one")
    second = package_deployment_kit(kit, output_directory=tmp_path / "dist-two")

    assert first.manifest and second.manifest
    assert first.manifest.zip_sha256 == second.manifest.zip_sha256
    assert Path(first.zip_path).read_bytes() == Path(second.zip_path).read_bytes()
    checksum = Path(first.checksum_path).read_text(encoding="ascii")
    assert checksum == f"{first.manifest.zip_sha256}  {Path(first.zip_path).name}\n"
    with zipfile.ZipFile(first.zip_path) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert all(item.date_time == FIXED_ZIP_TIMESTAMP for item in archive.infolist())
        assert "deployment/manifest.json" in names
        assert not any(name.startswith(f"{kit.name}/") for name in names)
        assert "release-manifest.json" not in names
        assert "release-manifest.md" not in names
        assert "SMOKE-TEST.txt" not in names
        assert not any(name.endswith(".sha256.txt") for name in names)


def test_changed_indexed_input_changes_archive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    first = package_deployment_kit(kit, output_directory=tmp_path / "dist-one")
    source = kit / "prepared_gui.py"
    source.write_text(source.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    _update_index_hash(kit, "prepared_gui.py")
    second = package_deployment_kit(kit, output_directory=tmp_path / "dist-two")
    assert first.manifest.zip_sha256 != second.manifest.zip_sha256


def test_package_rejects_invalid_kit_and_output_inside_kit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    (kit / "prepared_gui.py").write_text("tampered", encoding="utf-8")
    with pytest.raises(PackageError, match="STATIC_VALID"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")

    kit = _generate_kit(monkeypatch, tmp_path / "second")
    with pytest.raises(PackageError, match="outside"):
        package_deployment_kit(kit, output_directory=kit / "distribution")


def test_dry_run_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    output = tmp_path / "not-created"
    before = _tree_snapshot(tmp_path)
    result = package_deployment_kit(kit, output_directory=output, dry_run=True)
    assert not result.generated
    assert not output.exists()
    assert result.preview.files_to_package
    assert _tree_snapshot(tmp_path) == before


def test_missing_manifest_version_requires_explicit_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    manifest_path = kit / "deployment" / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload.pop("application_version", None)
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _update_index_hash(kit, "deployment/manifest.json")
    with pytest.raises(PackageError, match="--version"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")
    result = package_deployment_kit(
        kit, output_directory=tmp_path / "dist", version="2.0.0"
    )
    assert result.manifest.application_version == "2.0.0"


def test_semantically_equal_explicit_version_controls_release_spelling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    manifest_path = kit / "deployment" / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["application_version"] = "1.0"
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _update_index_hash(kit, "deployment/manifest.json")
    result = package_deployment_kit(
        kit, output_directory=tmp_path / "dist", version="1.0.0"
    )
    assert result.manifest.application_version == "1.0.0"
    assert Path(result.zip_path).name.endswith("-v1.0.0.zip")


def test_approved_artifact_and_external_runtime_propagate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wheel = _make_wheel(tmp_path)
    kit = _generate_kit(
        monkeypatch,
        tmp_path,
        fixture="optional_map_app",
        extras=["map"],
        artifact=wheel,
    )
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    assert result.manifest.selected_extras == ["map"]
    assert result.manifest.approved_artifacts[0].filename == wheel.name
    smoke = Path(result.smoke_test_path).read_text(encoding="utf-8")
    assert "WebView2" in smoke
    assert "proxy-tools==0.1.0" in smoke


def test_release_manifest_has_no_absolute_developer_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    rendered = Path(result.manifest_json_path).read_text(encoding="utf-8")
    assert str(tmp_path) not in rendered


def test_release_sidecars_are_consistent_with_zip_and_deployment_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wheel = _make_wheel(tmp_path)
    kit = _generate_kit(
        monkeypatch,
        tmp_path,
        fixture="optional_map_app",
        extras=["map"],
        artifact=wheel,
    )
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    release = json.loads(Path(result.manifest_json_path).read_text(encoding="utf-8"))
    deployment = json.loads(
        (kit / "deployment" / "manifest.json").read_text(encoding="utf-8")
    )
    zip_path = Path(result.zip_path)
    markdown = Path(result.manifest_markdown_path).read_text(encoding="utf-8")
    assert release["zip_sha256"] == hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    assert release["zip_byte_size"] == zip_path.stat().st_size
    assert release["zip_sha256"] in markdown
    assert str(release["zip_byte_size"]) in markdown
    for field in (
        "deployment_fingerprint",
        "selected_extras",
        "pyproject_sha256",
        "lockfile_sha256",
        "approved_artifacts",
    ):
        assert release[field] == deployment[field]
    assert (
        release["assessment_repository_fingerprint"]
        == deployment["assessment_repository_fingerprint"]
    )
    for value in (
        release["deployment_fingerprint"],
        release["pyproject_sha256"],
        release["lockfile_sha256"],
        release["approved_artifacts"][0]["filename"],
        release["approved_artifacts"][0]["sha256"],
        "map",
    ):
        assert value in markdown
    assert str(tmp_path) not in markdown


def test_recorded_source_provenance_is_propagated_without_package_time_inference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    manifest_path = kit / "deployment" / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["source_revision"] = "1" * 40
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _update_index_hash(kit, "deployment/manifest.json")
    monkeypatch.setattr(
        "python_deployment_builder.analysis.assessor._git_revision",
        lambda root: pytest.fail("packaging must not inspect the current Git checkout"),
    )
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    assert result.manifest.source_revision == "1" * 40


def test_source_provenance_remains_frozen_after_repository_advances(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURES / "prepared_gui", source)
    git = source / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    ref = git / "refs" / "heads" / "main"
    old_revision = "a" * 40
    ref.write_text(old_revision + "\n", encoding="ascii")
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    generate_deployment_kit(
        MaterializedRepository(root=source, source=str(source), source_kind="local"),
        kit,
    )
    recorded = json.loads(
        (kit / "deployment" / "manifest.json").read_text(encoding="utf-8")
    )
    ref.write_text("b" * 40 + "\n", encoding="ascii")
    (source / "prepared_gui.py").write_text("advanced source", encoding="utf-8")

    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    assert result.manifest.source_revision == old_revision
    assert (
        result.manifest.assessment_repository_fingerprint
        == recorded["assessment_repository_fingerprint"]
    )


@pytest.mark.parametrize(
    ("relative", "replacement"),
    [
        ("prepared_gui.py", b"modified source"),
        ("deployment/runtime/manage.py", b"modified helper"),
    ],
)
def test_package_rejects_staged_source_and_helper_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative: str,
    replacement: bytes,
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    (kit / relative).write_bytes(replacement)
    with pytest.raises(PackageError, match="STATIC_VALID"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")


def test_package_rejects_added_cache_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    cache = kit / "__pycache__"
    cache.mkdir()
    (cache / "injected.pyc").write_bytes(b"cache")
    with pytest.raises(PackageError, match="STATIC_VALID"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")


def test_package_rejects_added_unindexed_application_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    (kit / "injected_module.py").write_text("INJECTED = True\n", encoding="utf-8")
    with pytest.raises(PackageError, match="STATIC_VALID"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")


def test_package_rejects_approved_artifact_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wheel = _make_wheel(tmp_path)
    kit = _generate_kit(
        monkeypatch,
        tmp_path,
        fixture="optional_map_app",
        extras=["map"],
        artifact=wheel,
    )
    (kit / "deployment" / "wheels" / wheel.name).write_bytes(b"modified wheel")
    with pytest.raises(PackageError, match="STATIC_VALID"):
        package_deployment_kit(kit, output_directory=tmp_path / "dist")


def test_determinism_ignores_directory_and_filesystem_mtimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    copied = tmp_path / "copied-elsewhere" / "kit"
    shutil.copytree(kit, copied)
    for path in [copied, *copied.rglob("*")]:
        os.utime(path, (946684800, 946684800))
    first = package_deployment_kit(kit, output_directory=tmp_path / "dist-one")
    second = package_deployment_kit(copied, output_directory=tmp_path / "dist-two")
    assert first.manifest.zip_sha256 == second.manifest.zip_sha256
    assert Path(first.zip_path).read_bytes() == Path(second.zip_path).read_bytes()


def test_generic_smoke_test_contains_no_application_specific_assumptions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    smoke = Path(result.smoke_test_path).read_text(encoding="utf-8").lower()
    assert "openai" not in smoke
    assert "image browsing" not in smoke
    assert "webview2" not in smoke
    assert "map feature" not in smoke


def test_safe_extraction_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape.txt", "unsafe")
    with pytest.raises(ArchiveSafetyError, match="Unsafe"):
        safe_extract_zip(archive, tmp_path / "extracted")
    assert not (tmp_path / "escape.txt").exists()


def test_extracted_package_is_static_valid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _generate_kit(monkeypatch, tmp_path)
    result = package_deployment_kit(kit, output_directory=tmp_path / "dist")
    extracted = tmp_path / "extracted"
    safe_extract_zip(Path(result.zip_path), extracted)
    assert validate_static_kit(extracted).final_state.value == "STATIC_VALID"


@pytest.mark.parametrize(
    ("display", "expected"),
    [
        ("Geo Map Exp Extractor", "GeoMapExpExtractor"),
        ("CON", "ApplicationCON"),
        ("../unsafe:*?", "Unsafe"),
    ],
)
def test_release_filename_slug_is_safe(display: str, expected: str) -> None:
    assert safe_application_slug(display, "fallback-app") == expected
