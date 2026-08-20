from __future__ import annotations

import csv
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.cli import build_parser
from python_deployment_builder.generation.acquisition import (
    PreparationError,
    acquire_pinned_uv,
    extract_verified_uv,
    verify_uv_version,
)
from python_deployment_builder.generation.artifacts import validate_approved_wheel
from python_deployment_builder.generation.cmd import parse_certutil_sha256
from python_deployment_builder.generation.generator import (
    _render_owned_files,
    generate_deployment_kit,
)
from python_deployment_builder.generation.manifest import build_deployment_manifest
from python_deployment_builder.generation.preparation import (
    LockPreparationResult,
    prepare_lockfile,
)
from python_deployment_builder.generation.security import redact_secrets
from python_deployment_builder.generation.structural import validate_rendered_files
from python_deployment_builder.generation.templates import TEMPLATE_ROOT
from python_deployment_builder.models import BootstrapArtifact
from python_deployment_builder.planning.planner import create_deployment_plan

FIXTURES = Path(__file__).parent / "fixtures"


def _repository(name: str) -> MaterializedRepository:
    root = FIXTURES / name
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def _plan(name: str = "prepared_gui", extras: list[str] | None = None):
    repository = _repository(name)
    return create_deployment_plan(
        assess_repository(repository),
        selected_extras=extras or [],
        repository_root=repository.root,
    )


def _make_wheel(path: Path, name: str = "proxy-tools", version: str = "0.1.0") -> Path:
    normalized = name.replace("-", "_")
    wheel = path / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = f"{normalized}-{version}.dist-info"
    files = {
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{normalized}/__init__.py": "",
    }
    record_name = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for filename in files:
        writer.writerow((filename, "", ""))
    writer.writerow((record_name, "", ""))
    files[record_name] = output.getvalue()
    with zipfile.ZipFile(wheel, "w") as bundle:
        for filename, data in files.items():
            bundle.writestr(filename, data)
    return wheel


def _load_template_module(name: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(TEMPLATE_ROOT))
    spec = importlib.util.spec_from_file_location(f"generated_{name}", TEMPLATE_ROOT / name)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_cli_parses_repeatable_inputs() -> None:
    arguments = build_parser().parse_args(
        [
            "generate",
            "repo",
            "--extra",
            "map",
            "--extra",
            "reports",
            "--artifact",
            r"proxy-tools=C:\wheels\proxy.whl",
            "--bootstrap",
            "online_cmd",
            "--system-certs",
            "--prepare-lock",
            "--dry-run",
        ]
    )
    assert arguments.extra == ["map", "reports"]
    assert arguments.bootstrap == "online_cmd"
    assert arguments.system_certs and arguments.prepare_lock and arguments.dry_run


def test_dry_run_makes_no_output_or_lock(tmp_path: Path) -> None:
    repository = _repository("target_app")
    output = tmp_path / "kit"

    result = generate_deployment_kit(
        repository,
        output,
        prepare_lock=True,
        dry_run=True,
    )

    assert not output.exists()
    assert not (repository.root / "uv.lock").exists()
    assert not result.generated
    assert "uv.lock" in result.preview.files_to_create
    assert any("Create uv.lock" in item for item in result.preview.developer_actions)


def test_dry_run_reports_unowned_output_collision(tmp_path: Path) -> None:
    output = tmp_path / "kit"
    output.mkdir()
    (output / "Run Prepared Gui.bat").write_text("user file", encoding="utf-8")

    result = generate_deployment_kit(_repository("prepared_gui"), output, dry_run=True)

    assert result.preview.collisions == ["Run Prepared Gui.bat"]


def test_generation_writes_structurally_valid_kit_and_protects_edits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
    output = tmp_path / "kit"

    result = generate_deployment_kit(_repository("prepared_gui"), output)

    assert result.generated and result.manifest is not None
    assert (output / "deployment" / "manifest.json").is_file()
    assert (output / "deployment" / "bootstrap" / "uv.exe").read_bytes() == fake_uv.read_bytes()
    assert (output / "prepared_gui.py").is_file()
    assert not list(output.rglob("*.ps1"))

    run_bat = output / "Run Prepared Gui.bat"
    run_bat.write_text("locally modified", encoding="utf-8")
    preview = generate_deployment_kit(
        _repository("prepared_gui"), output, dry_run=True
    ).preview
    assert any("previously generated file was modified" in item for item in preview.collisions)


def test_manifest_renders_flat_source_system_certs_and_selected_extra(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path)
    approved, _path = validate_approved_wheel(f"proxy-tools={wheel}", plan)
    manifest = build_deployment_manifest(
        plan,
        FIXTURES / "optional_map_app",
        bootstrap_mode="online_cmd",
        system_certs=True,
        approved_artifacts=[approved],
        bundled_uv_sha256=None,
        referenced_files=["pyproject.toml", "uv.lock"],
    )

    assert manifest.source_roots == ["."]
    assert manifest.system_certs
    assert manifest.selected_extras == ["map"]
    assert manifest.sync_arguments[-2:] == ["--no-install-package", "proxy-tools"]
    assert manifest.approved_artifacts[0].sha256


def test_src_manifest_uses_src_root() -> None:
    plan = _plan("target_app")
    lock = FIXTURES / "target_app" / "uv.lock"
    lock.write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n', encoding="utf-8"
    )
    try:
        manifest = build_deployment_manifest(
            plan,
            FIXTURES / "target_app",
            bootstrap_mode="online_cmd",
            system_certs=False,
            approved_artifacts=[],
            bundled_uv_sha256=None,
            referenced_files=["pyproject.toml", "uv.lock"],
        )
    finally:
        lock.unlink()
    assert manifest.source_roots == ["src"]


def test_templates_are_thin_and_forbid_prohibited_shells(tmp_path: Path) -> None:
    plan = _plan()
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    owned, manifest = _render_owned_files(
        plan,
        FIXTURES / "prepared_gui",
        bootstrap_mode="bundled_uv",
        system_certs=False,
        approved=[],
        bundled_uv=fake_uv,
    )
    owned["deployment/generated-files.json"] = b"{}"
    files = {
        "pyproject.toml": (FIXTURES / "prepared_gui" / "pyproject.toml").read_bytes(),
        "uv.lock": (FIXTURES / "prepared_gui" / "uv.lock").read_bytes(),
        **owned,
    }

    checks = validate_rendered_files(
        files, manifest, generated_paths=set(owned), secret_values=[]
    )

    text = b"\n".join(owned.values()).lower()
    assert b"powershell.exe" not in text
    assert b"pwsh.exe" not in text
    assert b"executionpolicy" not in text
    assert not any(path.endswith(".ps1") for path in owned)
    assert "deployment/bootstrap/uv.exe" in owned
    assert any(item.code == "NO_FORBIDDEN_SHELL" for item in checks)


def test_uv_archive_rejects_traversal_and_hash_version_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "uv.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../uv.exe", b"bad")
    with pytest.raises(PreparationError, match="unsafe"):
        extract_verified_uv(archive, tmp_path / "uv.exe")

    result = subprocess.CompletedProcess([], 0, "uv 9.9.9", "")
    with pytest.raises(PreparationError, match="expected uv 0.12.5"):
        verify_uv_version(tmp_path / "uv.exe", "0.12.5", runner=lambda *a, **k: result)


def test_developer_uv_acquisition_rejects_sha_mismatch(tmp_path: Path) -> None:
    artifact = BootstrapArtifact(
        version="0.12.5",
        architecture="x86_64",
        url="https://example.invalid/uv.zip",
        sha256="0" * 64,
    )

    def opener(*args, **kwargs):
        return io.BytesIO(b"not the pinned archive")

    with pytest.raises(PreparationError, match="SHA-256 mismatch"):
        acquire_pinned_uv(artifact, cache_root=tmp_path, opener=opener)


def test_localized_certutil_output_is_parsed_structurally() -> None:
    expected = "4c" * 32
    spaced = " ".join(expected[index : index + 2] for index in range(0, 64, 2))
    output = f"SHA256-Hash von Datei:\n  {spaced}\nBefehl erfolgreich."
    assert parse_certutil_sha256(output) == expected
    with pytest.raises(PreparationError):
        parse_certutil_sha256("CertUtil: command failed")


def test_lock_preparation_requires_authorization_and_checks_existing(tmp_path: Path) -> None:
    plan = _plan()
    with pytest.raises(PreparationError, match="--prepare-lock"):
        prepare_lockfile(
            tmp_path,
            plan,
            tmp_path / "uv.exe",
            allow_create=False,
            system_certs=False,
        )

    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    result = prepare_lockfile(
        tmp_path,
        plan,
        tmp_path / "uv.exe",
        allow_create=False,
        system_certs=True,
        runner=runner,
    )
    assert result.checked and not result.created
    assert calls[0][0][-4:] == ["lock", "--check", "--python", "3.12"]
    assert calls[0][1]["env"]["UV_SYSTEM_CERTS"] == "true"


def test_explicit_lock_preparation_creates_then_checks(tmp_path: Path) -> None:
    plan = _plan()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["lock", "--python"]:
            (tmp_path / "uv.lock").write_text("created", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = prepare_lockfile(
        tmp_path,
        plan,
        tmp_path / "uv.exe",
        allow_create=True,
        system_certs=False,
        runner=runner,
    )

    assert result.created and result.checked
    assert calls[0][1:] == ["lock", "--python", "3.12"]
    assert calls[1][1:] == ["lock", "--check", "--python", "3.12"]


def test_approved_wheel_rejects_wrong_name_version_and_metadata(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path)
    approved, path = validate_approved_wheel(f"proxy-tools={wheel}", plan)
    assert path == wheel.resolve()
    assert approved.distribution_name == "proxy-tools"
    assert approved.version == "0.1.0"
    assert approved.sha256

    with pytest.raises(PreparationError, match="name mismatch"):
        validate_approved_wheel(f"other={wheel}", plan)
    wrong = _make_wheel(tmp_path, version="0.2.0")
    with pytest.raises(PreparationError, match="version mismatch"):
        validate_approved_wheel(f"proxy-tools={wrong}", plan)


def test_runtime_common_staleness_and_deletion_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    common = _load_template_module("runtime_common.py", monkeypatch)
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("project", encoding="utf-8")
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    app_root = local / "PythonDeploymentBuilder" / "apps" / "sample"
    environment = app_root / "env"
    (environment / "Scripts").mkdir(parents=True)
    (environment / "Scripts" / "python.exe").touch()
    (environment / "Scripts" / "pythonw.exe").touch()
    manifest = {
        "schema_version": "1.0",
        "application_id": "sample",
        "deployment_fingerprint": "fingerprint",
        "uv_version": "0.12.5",
        "python_version": "3.12",
        "pyproject_sha256": common.sha256_file(project / "pyproject.toml"),
        "lockfile_sha256": common.sha256_file(project / "uv.lock"),
        "selected_extras_fingerprint": "extras",
        "approved_artifacts": [],
        "runtime_paths": {
            "application_root": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample",
            "environment_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\env",
            "logs_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\logs",
            "state_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\state",
        },
    }
    common.write_state(manifest, project, "now")
    assert common.stale_reasons(manifest, project) == []
    (project / "uv.lock").write_text("changed", encoding="utf-8")
    assert "lockfile_sha256 changed" in common.stale_reasons(manifest, project)
    with pytest.raises(common.DeploymentRuntimeError, match="unsafe"):
        common.safe_remove_environment(manifest, tmp_path / "unrelated")


def test_webview2_registry_probe_and_project_write_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    diagnostics = _load_template_module("diagnostics.py", monkeypatch)
    calls = []

    def read_value(hive, path, view):
        calls.append((hive, path, view))
        return "123.4.5.6" if hive == "HKCU" else None

    result = diagnostics.detect_webview2(read_value)
    assert result["installed"] and result["version"] == "123.4.5.6"
    assert any("F3017226-FE2A-4295-8BDF-00C3A9A7E4C5" in item[1] for item in calls)

    launch = _load_template_module("launch.py", monkeypatch)
    launch.probe_project_write(tmp_path, "Test App")
    assert not list(tmp_path.glob(".pdbuilder-write-probe-*"))


def test_gui_uses_pythonw_and_console_uses_python() -> None:
    manage = (TEMPLATE_ROOT / "manage.py").read_text(encoding="utf-8")
    assert '"pythonw.exe" if manifest["entry_point_kind"] == "gui" else "python.exe"' in manage
    bootstrap = (TEMPLATE_ROOT / "bootstrap.cmd.tmpl").read_text(encoding="utf-8")
    assert "curl.exe --fail --location" in bootstrap
    assert "certutil.exe -hashfile" in bootstrap
    assert "tar.exe -xf" in bootstrap


@pytest.mark.parametrize("helper", ["manage.py", "launch.py", "diagnostics.py"])
def test_generated_helpers_import_siblings_with_production_flags(
    helper: str, tmp_path: Path
) -> None:
    runtime = tmp_path / "deployment" / "runtime"
    runtime.mkdir(parents=True)
    for name in ("runtime_common.py", "manage.py", "launch.py", "diagnostics.py"):
        shutil.copy2(TEMPLATE_ROOT / name, runtime / name)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(TEMPLATE_ROOT.parent)
    result = subprocess.run(
        [sys.executable, "-B", "-E", "-s", str(runtime / helper), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    assert not (runtime / "__pycache__").exists()


def test_secret_value_is_not_rendered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = "sk-test-value-that-must-not-leak"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    plan = _plan("target_app")
    lock = FIXTURES / "target_app" / "uv.lock"
    lock.write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n', encoding="utf-8"
    )
    try:
        fake_uv = tmp_path / "uv.exe"
        fake_uv.write_bytes(b"verified")
        owned, _manifest = _render_owned_files(
            plan,
            FIXTURES / "target_app",
            bootstrap_mode="bundled_uv",
            system_certs=False,
            approved=[],
            bundled_uv=fake_uv,
        )
    finally:
        lock.unlink()
    assert secret.encode() not in b"".join(owned.values())
    assert secret not in redact_secrets(f"OPENAI_API_KEY={secret}")
