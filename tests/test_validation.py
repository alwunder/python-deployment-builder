from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.cli import build_parser
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.models import (
    DeploymentManifest,
    ValidationCheckStatus,
    ValidationFinalState,
)
from python_deployment_builder.packaging import package_deployment_kit
from python_deployment_builder.reporting.json_report import write_validation_reports
from python_deployment_builder.validation.runtime import (
    APPLICATION_PROBE,
    _application_probe_result,
    _runtime_environment,
    _scenario_copy,
    validate_runtime_kit,
)
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


def _refresh_manifest_index(kit: Path) -> None:
    index_path = kit / "deployment/generated-files.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    manifest = kit / "deployment/manifest.json"
    for item in index["files"]:
        if item["path"] == "deployment/manifest.json":
            item["sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")


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


def test_pre_m61_source_manifest_defaults_remain_statically_compatible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    manifest_path = kit / "deployment/manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload.pop("application_artifact", None)
    payload.pop("configuration_secret_names", None)
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _refresh_manifest_index(kit)

    manifest = DeploymentManifest.model_validate(payload)
    report = validate_static_kit(kit)
    packaged = package_deployment_kit(kit, output_directory=tmp_path / "release")

    assert manifest.application_artifact is None
    assert manifest.configuration_secret_names == []
    assert report.final_state == ValidationFinalState.STATIC_VALID
    assert packaged.generated


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
    cache = kit / "deployment" / "runtime" / "__pycache__ (1)"
    cache.mkdir()
    (cache / "runtime_common.pyc").write_bytes(b"validation mutation")

    report = validate_static_kit(kit)

    assert _status(report, "NO_RUNTIME_CACHES") == ValidationCheckStatus.FAIL


def test_runtime_validation_preserves_controlled_localappdata_after_config_scrub(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    manifest = DeploymentManifest.model_validate_json(
        (kit / "deployment/manifest.json").read_text(encoding="utf-8")
    )
    manifest.configuration_presence_names.append("LOCALAPPDATA")
    isolated = tmp_path / "isolated-local-app-data"

    environment = _runtime_environment(manifest, isolated)

    assert environment["LOCALAPPDATA"] == str(isolated)


def test_runtime_scenario_copy_preserves_staged_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kit = _kit(monkeypatch, tmp_path)
    manifest = DeploymentManifest.model_validate_json(
        (kit / "deployment/manifest.json").read_text(encoding="utf-8")
    )
    for directory, filename in (
        ("wheels", "approved.whl"),
        ("application", "application.whl"),
    ):
        artifact = kit / "deployment" / directory / filename
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(directory.encode())

    scenario = _scenario_copy(kit, tmp_path / "scenario", manifest, {})

    assert (scenario / "deployment/wheels/approved.whl").read_bytes() == b"wheels"
    assert (
        scenario / "deployment/application/application.whl"
    ).read_bytes() == b"application"


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


@pytest.mark.parametrize(
    ("expected", "installed"),
    [("1.0-rc1", "1.0rc1"), ("1.0-1", "1.0.post1")],
)
def test_runtime_application_probe_compares_pep440_versions_semantically(
    expected: str, installed: str
) -> None:
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps({"version": installed, "module_found": True, "error": None}),
        stderr="",
    )

    accepted, evidence = _application_probe_result(completed, expected)

    assert accepted
    assert f"Expected application version: {expected}" in evidence
    assert f"Installed application version: {installed}" in evidence


def test_runtime_application_probe_rejects_different_or_invalid_version() -> None:
    for installed in ("2.0", "not a version"):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"version": installed, "module_found": True, "error": None}),
            stderr="",
        )

        accepted, _evidence = _application_probe_result(completed, "1.0")

        assert not accepted


def test_managed_application_probe_uses_only_standard_library() -> None:
    environment = {
        **os.environ,
        "PDBUILDER_APPLICATION_DISTRIBUTION": "distribution-that-does-not-exist",
        "PDBUILDER_APPLICATION_MODULE": "json",
    }

    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", APPLICATION_PROBE],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["error"] == "PackageNotFoundError"
    assert "packaging" not in APPLICATION_PROBE


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


def test_package_runtime_installs_artifacts_in_order_and_states_success_last(
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
    spec = importlib.util.spec_from_file_location("ordered_manage", template_root / "manage.py")
    assert spec and spec.loader
    manage = importlib.util.module_from_spec(spec)
    sys.modules["ordered_manage"] = manage
    spec.loader.exec_module(manage)

    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    project = tmp_path / "project"
    project.mkdir()
    deployment = tmp_path / "deployment"
    (deployment / "wheels").mkdir(parents=True)
    (deployment / "application").mkdir()
    dependency = deployment / "wheels/dependency.whl"
    application = deployment / "application/application.whl"
    dependency.write_bytes(b"dependency")
    application.write_bytes(b"application")
    monkeypatch.setattr(manage, "deployment_directory", lambda: deployment)
    app_root = local / "PythonDeploymentBuilder/apps/sample"
    environment = app_root / "env"
    events: list[str] = []
    manifest = {
        "application_id": "sample",
        "runtime_paths": {
            "application_root": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample",
            "environment_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\env",
            "logs_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\logs",
            "state_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\state",
        },
        "runtime_environment": {},
        "sync_arguments": ["sync", "--locked", "--no-build"],
        "approved_artifacts": [{"filename": dependency.name}],
        "application_artifact": {"filename": application.name},
    }

    def record(command, **kwargs):
        if command[1] == "sync":
            events.append("locked-sync")
            (environment / "Scripts").mkdir(parents=True)
            (environment / "Scripts/python.exe").write_bytes(b"python")
            (environment / "Scripts/pythonw.exe").write_bytes(b"pythonw")
        elif str(dependency) in command:
            events.append("dependency-artifact")
        elif str(application) in command:
            events.append("application-wheel")
        elif "check" in command and command[1:3] == ["pip", "check"]:
            events.append("pip-check")
        else:
            events.append("entry-point-check")

    monkeypatch.setattr(manage, "run_logged", record)
    monkeypatch.setattr(
        manage,
        "write_state",
        lambda *args: events.append("state-success"),
    )

    manage._promote_environment(
        manifest, project, tmp_path / "uv.exe", manage.logging.getLogger("test-order")
    )

    assert events == [
        "locked-sync",
        "dependency-artifact",
        "application-wheel",
        "pip-check",
        "entry-point-check",
        "state-success",
    ]


def test_package_runtime_application_install_failure_restores_previous_environment(
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
    spec = importlib.util.spec_from_file_location(
        "application_failure_manage", template_root / "manage.py"
    )
    assert spec and spec.loader
    manage = importlib.util.module_from_spec(spec)
    sys.modules["application_failure_manage"] = manage
    spec.loader.exec_module(manage)

    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    project = tmp_path / "project"
    project.mkdir()
    deployment = tmp_path / "deployment"
    (deployment / "application").mkdir(parents=True)
    application = deployment / "application/application.whl"
    application.write_bytes(b"application")
    monkeypatch.setattr(manage, "deployment_directory", lambda: deployment)
    app_root = local / "PythonDeploymentBuilder/apps/sample"
    environment = app_root / "env"
    (environment / "Scripts").mkdir(parents=True)
    old_python = environment / "Scripts/python.exe"
    old_python.write_bytes(b"known-good")
    (environment / "Scripts/pythonw.exe").write_bytes(b"known-good")
    state_writes: list[str] = []
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
        "application_artifact": {"filename": application.name},
    }

    def fail_application(command, **kwargs):
        if command[1] == "sync":
            (environment / "Scripts").mkdir(parents=True)
            (environment / "Scripts/python.exe").write_bytes(b"candidate")
            (environment / "Scripts/pythonw.exe").write_bytes(b"candidate")
            return
        raise manage.DeploymentRuntimeError("controlled application install failure")

    monkeypatch.setattr(manage, "run_logged", fail_application)
    monkeypatch.setattr(manage, "write_state", lambda *args: state_writes.append("written"))

    with pytest.raises(manage.DeploymentRuntimeError, match="application install failure"):
        manage._promote_environment(
            manifest, project, tmp_path / "uv.exe", manage.logging.getLogger("test-app-fail")
        )

    assert old_python.read_bytes() == b"known-good"
    assert not state_writes
    assert not (app_root / "env.previous").exists()
    assert not (app_root / "env.failed").exists()
