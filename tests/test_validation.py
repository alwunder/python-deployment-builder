from __future__ import annotations

import json
from pathlib import Path

import pytest

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.cli import build_parser
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.models import (
    ValidationCheckStatus,
    ValidationFinalState,
)
from python_deployment_builder.reporting.json_report import write_validation_reports
from python_deployment_builder.validation.runtime import validate_runtime_kit
from python_deployment_builder.validation.static import validate_static_kit

FIXTURES = Path(__file__).parent / "fixtures"


def _repository() -> MaterializedRepository:
    root = FIXTURES / "prepared_gui"
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def _kit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, system_certs=False) -> Path:
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
    generate_deployment_kit(_repository(), output, system_certs=system_certs)
    return output


def _status(report, code: str) -> ValidationCheckStatus:
    return next(item.status for item in report.static_checks if item.code == code)


def test_validate_cli_defaults_static_and_requires_explicit_runtime() -> None:
    static = build_parser().parse_args(["validate", "kit"])
    runtime = build_parser().parse_args(
        ["validate", "kit", "--runtime", "--runtime-root", "state", "--dry-run"]
    )

    assert static.validation_mode == "static"
    assert runtime.validation_mode == "runtime"
    assert runtime.runtime_root == Path("state")
    assert runtime.dry_run


def test_static_kit_validation_and_report_serialization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path, system_certs=True)

    report = validate_static_kit(kit)
    json_path, markdown_path = write_validation_reports(report, tmp_path / "reports")

    assert report.final_state == ValidationFinalState.STATIC_VALID, [
        (item.code, item.status, item.detail, item.evidence)
        for item in report.static_checks
        if item.status == ValidationCheckStatus.FAIL
    ]
    assert all(item.status == ValidationCheckStatus.PASS for item in report.static_checks)
    assert _status(report, "SYSTEM_CERTS_PROPAGATION") == ValidationCheckStatus.PASS
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema_version"] == "1.0"
    assert "STATIC_VALID" in markdown_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("relative", "code"),
    [
        ("deployment/runtime/launch.py", "GENERATED_FILE_HASHES"),
        ("uv.lock", "PROJECT_METADATA_HASHES"),
        ("deployment/bootstrap/uv.exe", "BUNDLED_UV_HASH"),
    ],
)
def test_static_validation_detects_hash_mismatch(
    relative: str,
    code: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    path = kit / relative
    path.write_bytes(path.read_bytes() + b"changed")

    report = validate_static_kit(kit)

    assert report.final_state == ValidationFinalState.FAILED
    assert _status(report, code) == ValidationCheckStatus.FAIL


def test_static_validation_detects_missing_helper_and_forbidden_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    (kit / "deployment/runtime/diagnostics.py").unlink()
    bootstrap = kit / "deployment/bootstrap/bootstrap.cmd"
    bootstrap.write_text(
        bootstrap.read_text(encoding="utf-8") + "\npowershell.exe -ExecutionPolicy Bypass\n",
        encoding="utf-8",
    )

    report = validate_static_kit(kit)

    assert _status(report, "LAUNCHERS_AND_HELPERS") == ValidationCheckStatus.FAIL
    assert _status(report, "NO_POWERSHELL") == ValidationCheckStatus.FAIL


def test_static_validation_detects_runtime_bytecode_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    cache = kit / "deployment" / "runtime" / "__pycache__"
    cache.mkdir()
    (cache / "runtime_common.pyc").write_bytes(b"validation mutation")

    report = validate_static_kit(kit)

    assert _status(report, "NO_RUNTIME_CACHES") == ValidationCheckStatus.FAIL


def test_runtime_dry_run_executes_nothing_and_creates_no_runtime_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    runtime_root = tmp_path / "runtime"

    report = validate_runtime_kit(kit, runtime_root, dry_run=True)

    assert not runtime_root.exists()
    assert report.validation_mode == "runtime"
    assert all(
        item.status == ValidationCheckStatus.PLANNED for item in report.runtime_checks
    )


def test_generated_runtime_rolls_back_after_setup_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import importlib.util
    import sys

    template_root = (
        Path(__file__).parents[1]
        / "src"
        / "python_deployment_builder"
        / "templates"
        / "windows_uv"
    )
    monkeypatch.syspath_prepend(str(template_root))
    spec = importlib.util.spec_from_file_location("rollback_manage", template_root / "manage.py")
    assert spec and spec.loader
    manage = importlib.util.module_from_spec(spec)
    sys.modules["rollback_manage"] = manage
    spec.loader.exec_module(manage)

    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("project", encoding="utf-8")
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    app_root = local / "PythonDeploymentBuilder" / "apps" / "sample"
    environment = app_root / "env"
    (environment / "Scripts").mkdir(parents=True)
    python = environment / "Scripts" / "python.exe"
    python.write_text("working", encoding="utf-8")
    (environment / "Scripts" / "pythonw.exe").write_text("working", encoding="utf-8")
    manifest = {
        "application_id": "sample",
        "runtime_paths": {
            "application_root": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample",
            "environment_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\env",
            "logs_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\logs",
            "state_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\state",
        },
        "runtime_environment": {},
        "sync_arguments": ["sync"],
        "approved_artifacts": [],
    }

    def controlled_failure(*args, **kwargs):
        raise manage.DeploymentRuntimeError("controlled failure")

    monkeypatch.setattr(manage, "run_logged", controlled_failure)
    with pytest.raises(manage.DeploymentRuntimeError, match="controlled failure"):
        manage._promote_environment(
            manifest,
            project,
            tmp_path / "uv.exe",
            manage.logging.getLogger("test-rollback"),
        )

    assert python.read_text(encoding="utf-8") == "working"
    assert not (app_root / "env.previous").exists()
    assert not (app_root / "env.failed").exists()
