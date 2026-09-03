"""Explicit developer-side runtime validation of a staged Windows kit."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.security import redact_secrets
from python_deployment_builder.models import (
    DeploymentManifest,
    ExternalRuntimeValidation,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationFinalState,
    ValidationReport,
)
from python_deployment_builder.validation.static import validate_static_kit

SETUP_REQUIRED = 20
HELPER_FLAGS = ("-B", "-E", "-s")


def _check(
    code: str,
    phase: str,
    status: ValidationCheckStatus,
    detail: str,
    *,
    evidence: list[str] | None = None,
    duration: float | None = None,
) -> ValidationCheckResult:
    return ValidationCheckResult(
        code=code,
        phase=phase,
        status=status,
        detail=detail,
        evidence=evidence or [],
        duration_seconds=duration,
    )


def _manifest(root: Path) -> DeploymentManifest:
    return DeploymentManifest.model_validate_json(
        (root / "deployment" / "manifest.json").read_text(encoding="utf-8")
    )


def _expand(value: str, local_app_data: Path) -> Path:
    return Path(value.replace("%LOCALAPPDATA%", str(local_app_data))).resolve()


def _runtime_environment(
    manifest: DeploymentManifest, local_app_data: Path
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PDBUILDER_NO_PAUSE"] = "1"
    for name in manifest.configuration_presence_names:
        environment.pop(name, None)
    # LOCALAPPDATA is controlled by the validation harness even when target
    # analysis records it as a configuration read. Do not let redaction/isolation
    # remove the runtime root that the generated Windows bootstrap requires.
    environment["LOCALAPPDATA"] = str(local_app_data)
    for key, value in manifest.runtime_environment.items():
        if "%PROJECT_ROOT%" not in value:
            environment[key] = value.replace("%LOCALAPPDATA%", str(local_app_data))
    environment["UV_NO_ENV_FILE"] = "1"
    if manifest.system_certs:
        environment["UV_SYSTEM_CERTS"] = "true"
    else:
        environment.pop("UV_SYSTEM_CERTS", None)
    return environment


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log_handle,
    timeout: int = 900,
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    duration = time.perf_counter() - started
    log_handle.write(f"\n$ {redact_secrets(subprocess.list2cmdline(command))}\n")
    log_handle.write(f"exit={result.returncode} duration={duration:.3f}s\n")
    if result.stdout:
        log_handle.write(redact_secrets(result.stdout))
    if result.stderr:
        log_handle.write(redact_secrets(result.stderr))
    log_handle.flush()
    return result, duration


def _tree_signature(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.is_dir():
        return "missing"
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        stat = path.stat()
        digest.update(str(path.relative_to(root)).encode())
        digest.update(str(stat.st_size).encode())
        digest.update(str(stat.st_mtime_ns).encode())
    return digest.hexdigest()


def _failure_category(output: str) -> str:
    lowered = output.lower()
    if any(token in lowered for token in ("certificate", "tls", "ssl")):
        return "certificate_trust_failure"
    if any(
        token in lowered
        for token in ("timed out", "could not connect", "dns", "network is unreachable")
    ):
        return "network_unreachable_or_policy_block"
    if any(token in lowered for token in ("no solution found", "not found in the package")):
        return "package_resolution_or_artifact_unavailable"
    if any(token in lowered for token in ("failed to build", "source distribution")):
        return "source_build_required_but_prohibited"
    if "incorrect function" in lowered:
        return "runtime_root_filesystem_incompatible"
    return "command_failure"


def _scenario_copy(
    kit_root: Path,
    scenario_root: Path,
    manifest: DeploymentManifest,
    changes: dict[str, object],
) -> Path:
    scenario_root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(kit_root / "deployment" / "runtime", scenario_root / "deployment" / "runtime")
    (scenario_root / "deployment").mkdir(exist_ok=True)
    payload = manifest.model_dump(mode="json")
    payload.update(changes)
    (scenario_root / "deployment" / "manifest.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    shutil.copy2(kit_root / "pyproject.toml", scenario_root / "pyproject.toml")
    shutil.copy2(kit_root / "uv.lock", scenario_root / "uv.lock")
    for artifact_directory in ("wheels", "application"):
        source = kit_root / "deployment" / artifact_directory
        if source.is_dir():
            shutil.copytree(source, scenario_root / "deployment" / artifact_directory)
    return scenario_root


def _find_bat(root: Path, prefix: str) -> Path:
    matches = sorted(root.glob(f"{prefix}*.bat"))
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {prefix.strip()} BAT, found {len(matches)}.")
    return matches[0]


def _selected_imports(kit_root: Path, manifest: DeploymentManifest) -> list[str]:
    repository = MaterializedRepository(
        root=kit_root,
        source=str(kit_root),
        source_kind="local",
    )
    assessment = assess_repository(repository)
    selected_groups = {"runtime", *manifest.selected_extras}
    imports = {
        name
        for dependency in assessment.dependencies
        if dependency.group in selected_groups
        for name in dependency.import_names
    }
    if any(
        item.category == "gui_framework" and "tkinter" in item.name.lower()
        for item in assessment.runtime_requirements
    ):
        imports.add("tkinter")
    return sorted(imports)


def _planned_runtime_checks(report: ValidationReport) -> ValidationReport:
    report.validation_mode = "runtime"
    report.dry_run = True
    report.runtime_checks = [
        _check(
            "RUNTIME_PLAN",
            "first_run",
            ValidationCheckStatus.PLANNED,
            "Would verify bundled uv, provision managed Python, and perform locked/no-build "
            "setup in an isolated LocalAppData root.",
        ),
        _check(
            "HELPER_SUBPROCESS_PLAN",
            "first_run",
            ValidationCheckStatus.PLANNED,
            "Would execute generated helpers with -E -s and run entry-point/import/write checks.",
        ),
        _check(
            "LIFECYCLE_PLAN",
            "fast_path",
            ValidationCheckStatus.PLANNED,
            "Would exercise fast path, controlled staleness, rollback, repair, and diagnostics "
            "without launching the GUI.",
        ),
    ]
    return report


def validate_runtime_kit(
    kit_root: Path,
    runtime_root: Path,
    *,
    dry_run: bool = False,
) -> ValidationReport:
    """Install and exercise a staged kit only after explicit runtime selection."""

    root = kit_root.resolve()
    runtime_root = runtime_root.resolve()
    report = validate_static_kit(root, dry_run=dry_run)
    report.validation_mode = "runtime"
    report.runtime_root = str(runtime_root)
    if dry_run:
        return _planned_runtime_checks(report)
    if report.final_state == ValidationFinalState.FAILED:
        return report
    if platform.system() != "Windows":
        report.runtime_checks.append(
            _check(
                "WINDOWS_HOST",
                "first_run",
                ValidationCheckStatus.FAIL,
                "The Windows deployment runtime can only be validated on Windows.",
            )
        )
        report.final_state = ValidationFinalState.FAILED
        return report

    manifest = _manifest(root)
    runtime_root.mkdir(parents=True, exist_ok=True)
    validation_logs = runtime_root / "validation-logs"
    validation_logs.mkdir(parents=True, exist_ok=True)
    validation_log = validation_logs / "runtime-validation.log"
    report.log_paths.append(str(validation_log))
    local_app_data = runtime_root
    environment = _runtime_environment(manifest, local_app_data)
    app_root = _expand(manifest.runtime_paths.application_root, local_app_data)
    env_root = _expand(manifest.runtime_paths.environment_path, local_app_data)
    state_file = (
        _expand(manifest.runtime_paths.state_path, local_app_data)
        / "deployment-state.json"
    )
    uv = (
        root / "deployment" / "bootstrap" / "uv.exe"
        if manifest.bootstrap_mode == "bundled_uv"
        else _expand(manifest.runtime_paths.uv_executable, local_app_data)
    )

    # Windows Python packages can contain deeply nested generated modules. Keep
    # validation conservative even when the development host has partial long-path support.
    projected_deep_path = env_root / "Lib" / "site-packages" / ("x" * 90)
    if len(str(projected_deep_path)) >= 240:
        report.runtime_checks.append(
            _check(
                "RUNTIME_PATH_LENGTH",
                "first_run",
                ValidationCheckStatus.FAIL,
                "The isolated runtime root is too long for conservative Windows package imports.",
                evidence=[str(runtime_root), f"projected_length={len(str(projected_deep_path))}"],
            )
        )
        report.final_state = ValidationFinalState.FAILED
        return report

    def fail(code: str, phase: str, detail: str, evidence: list[str] | None = None) -> None:
        report.runtime_checks.append(
            _check(code, phase, ValidationCheckStatus.FAIL, detail, evidence=evidence)
        )
        report.final_state = ValidationFinalState.FAILED

    with validation_log.open("a", encoding="utf-8") as log:
        log.write(f"Validation started {datetime.now(UTC).isoformat()}\n")
        log.write(f"Kit: {root}\nRuntime root: {runtime_root}\n")

        diagnose_bat = _find_bat(root, "Diagnose ")
        before, duration = _run(
            ["cmd.exe", "/d", "/c", str(diagnose_bat)],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        report.runtime_checks.append(
            _check(
                "DIAGNOSTICS_BEFORE_SETUP",
                "diagnostics",
                ValidationCheckStatus.PASS
                if before.returncode == 0
                else ValidationCheckStatus.FAIL,
                "Diagnose BAT produced a pre-setup report without managed Python."
                if before.returncode == 0
                else "Diagnose BAT failed before setup.",
                evidence=[before.stdout[-1000:]],
                duration=duration,
            )
        )
        if before.returncode != 0:
            report.final_state = ValidationFinalState.FAILED
            return report

        version, duration = _run(
            [str(uv), "--version"], cwd=root, environment=environment, log_handle=log
        )
        version_ok = version.returncode == 0 and version.stdout.split()[:2] == [
            "uv",
            manifest.uv_version,
        ]
        report.runtime_checks.append(
            _check(
                "PINNED_UV_EXECUTES",
                "first_run",
                ValidationCheckStatus.PASS if version_ok else ValidationCheckStatus.FAIL,
                f"Bundled uv reports the pinned version {manifest.uv_version}."
                if version_ok
                else "Bundled uv did not execute at the pinned version.",
                evidence=[(version.stdout or version.stderr).strip()],
                duration=duration,
            )
        )
        if not version_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        python_root = _expand(manifest.runtime_paths.python_install_root, local_app_data)
        install_command = [
            str(uv),
            "python",
            "install",
            manifest.python_version,
            "--install-dir",
            str(python_root),
            "--no-bin",
            "--no-registry",
            "--managed-python",
        ]
        installed, install_duration = _run(
            install_command, cwd=root, environment=environment, log_handle=log
        )
        found, _find_duration = _run(
            [str(uv), "python", "find", manifest.python_version, "--managed-python"],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        managed_python = Path(found.stdout.strip()) if found.returncode == 0 else Path()
        python_ok = (
            installed.returncode == 0
            and found.returncode == 0
            and managed_python.is_file()
            and python_root in managed_python.parents
            and not (root / ".venv").exists()
        )
        report.runtime_checks.append(
            _check(
                "MANAGED_PYTHON_PROVISIONING",
                "first_run",
                ValidationCheckStatus.PASS if python_ok else ValidationCheckStatus.FAIL,
                "Managed Python was provisioned under the isolated planned root without a "
                "project .venv."
                if python_ok
                else "Managed Python provisioning or path isolation failed.",
                evidence=[
                    str(managed_python),
                    f"python_root={python_root}",
                    *(
                        [
                            "failure_category="
                            + _failure_category(installed.stderr or installed.stdout)
                        ]
                        if not python_ok
                        else []
                    ),
                ],
                duration=install_duration,
            )
        )
        if not python_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        helper_failures: list[str] = []
        for helper in ("manage.py", "launch.py", "diagnostics.py"):
            result, _duration = _run(
                [
                    str(managed_python),
                    *HELPER_FLAGS,
                    str(root / "deployment" / "runtime" / helper),
                    "--help",
                ],
                cwd=root,
                environment={**environment, "PYTHONPATH": str(runtime_root / "untrusted")},
                log_handle=log,
            )
            if result.returncode != 0:
                helper_failures.append(f"{helper}: {result.stderr.strip()}")
        report.runtime_checks.append(
            _check(
                "HELPER_SIBLING_IMPORTS",
                "first_run",
                ValidationCheckStatus.PASS if not helper_failures else ValidationCheckStatus.FAIL,
                "All generated helpers execute with -B -E -s and import their sibling modules."
                if not helper_failures
                else "A generated helper could not import its sibling modules.",
                evidence=helper_failures,
            )
        )
        if helper_failures:
            report.final_state = ValidationFinalState.FAILED
            return report

        manage = root / "deployment" / "runtime" / "manage.py"
        setup, setup_duration = _run(
            [
                str(managed_python),
                *HELPER_FLAGS,
                str(manage),
                "setup",
                "--project-root",
                str(root),
                "--uv",
                str(uv),
            ],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        app_python = env_root / "Scripts" / "python.exe"
        first_run_ok = (
            setup.returncode == 0
            and app_python.is_file()
            and (env_root / "Scripts" / "pythonw.exe").is_file()
            and state_file.is_file()
        )
        report.first_run_result = (
            ValidationCheckStatus.PASS if first_run_ok else ValidationCheckStatus.FAIL
        )
        report.runtime_checks.append(
            _check(
                "LOCKED_NO_BUILD_SETUP",
                "first_run",
                report.first_run_result,
                "Generated manage.py completed locked/no-build setup and recorded successful state."
                if first_run_ok
                else "Generated manage.py could not complete locked/no-build setup.",
                evidence=[
                    *(
                        ["failure_category=" + _failure_category(setup.stderr or setup.stdout)]
                        if not first_run_ok
                        else []
                    ),
                    (setup.stderr or setup.stdout)[-2000:],
                ],
                duration=setup_duration,
            )
        )
        if not first_run_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        if manifest.application_artifact is not None:
            application_probe_environment = {
                **environment,
                "PDBUILDER_APPLICATION_DISTRIBUTION": (
                    manifest.application_artifact.distribution_name
                ),
                "PDBUILDER_APPLICATION_VERSION": manifest.application_artifact.version,
                "PDBUILDER_APPLICATION_MODULE": manifest.entry_point_module,
            }
            application_probe = (
                "import importlib.metadata as m,importlib.util,os,sys;"
                "name=os.environ['PDBUILDER_APPLICATION_DISTRIBUTION'];"
                "version=os.environ['PDBUILDER_APPLICATION_VERSION'];"
                "module=os.environ['PDBUILDER_APPLICATION_MODULE'];"
                "sys.exit(m.version(name)!=version or importlib.util.find_spec(module) is None)"
            )
            installed_application, application_duration = _run(
                [str(app_python), *HELPER_FLAGS, "-c", application_probe],
                cwd=root,
                environment=application_probe_environment,
                log_handle=log,
            )
            application_ok = installed_application.returncode == 0
            report.runtime_checks.append(
                _check(
                    "APPLICATION_WHEEL_INSTALLED",
                    "first_run",
                    (
                        ValidationCheckStatus.PASS
                        if application_ok
                        else ValidationCheckStatus.FAIL
                    ),
                    "The exact first-party distribution/version and authoritative module are "
                    "installed in the managed environment."
                    if application_ok
                    else "The first-party application wheel is not installed as declared.",
                    evidence=[installed_application.stderr[-1000:]],
                    duration=application_duration,
                )
            )
            if not application_ok:
                report.final_state = ValidationFinalState.FAILED
                return report

        imports = _selected_imports(root, manifest)
        import_environment = {**environment, "PDBUILDER_IMPORTS_JSON": json.dumps(imports)}
        import_probe = (
            "import importlib,json,os;"
            "[importlib.import_module(n) for n in json.loads(os.environ['PDBUILDER_IMPORTS_JSON'])]"
        )
        imported, import_duration = _run(
            [str(app_python), *HELPER_FLAGS, "-c", import_probe],
            cwd=root,
            environment=import_environment,
            log_handle=log,
        )
        report.runtime_checks.append(
            _check(
                "DECLARED_IMPORTS",
                "first_run",
                ValidationCheckStatus.PASS
                if imported.returncode == 0
                else ValidationCheckStatus.FAIL,
                "Selected runtime dependency imports succeeded."
                if imported.returncode == 0
                else "One or more selected runtime dependency imports failed.",
                evidence=[f"imports={imports}", imported.stderr[-1000:]],
                duration=import_duration,
            )
        )
        if imported.returncode != 0:
            report.final_state = ValidationFinalState.FAILED
            return report

        no_dev_probe = (
            "import importlib.metadata as m,sys;"
            "bad=[n for n in ('pytest','ruff') if any(d.metadata['Name'].lower()==n "
            "for d in m.distributions())];print(','.join(bad));sys.exit(bool(bad))"
        )
        no_dev, no_dev_duration = _run(
            [str(app_python), *HELPER_FLAGS, "-c", no_dev_probe],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        report.runtime_checks.append(
            _check(
                "DEV_DEPENDENCIES_EXCLUDED",
                "first_run",
                ValidationCheckStatus.PASS
                if no_dev.returncode == 0
                else ValidationCheckStatus.FAIL,
                "pytest and Ruff are absent from the application environment."
                if no_dev.returncode == 0
                else "A development dependency was installed into the application environment.",
                evidence=[no_dev.stdout.strip()],
                duration=no_dev_duration,
            )
        )
        if no_dev.returncode != 0:
            report.final_state = ValidationFinalState.FAILED
            return report
        report.runtime_checks.append(
            _check(
                "CONFIGURATION_NOT_REQUIRED",
                "first_run",
                ValidationCheckStatus.PASS,
                "Setup and entry-point checks passed with secret configuration variables removed.",
                evidence=[f"{name} present: no" for name in manifest.configuration_presence_names],
            )
        )

        before_fast = (_tree_signature(env_root), _tree_signature(state_file.parent))
        fast, fast_duration = _run(
            [
                str(app_python),
                *HELPER_FLAGS,
                str(manage),
                "check",
                "--project-root",
                str(root),
            ],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        after_fast = (_tree_signature(env_root), _tree_signature(state_file.parent))
        fast_ok = fast.returncode == 0 and before_fast == after_fast
        report.fast_path_result = (
            ValidationCheckStatus.PASS if fast_ok else ValidationCheckStatus.FAIL
        )
        report.runtime_checks.append(
            _check(
                "FAST_PATH_NO_REBUILD",
                "fast_path",
                report.fast_path_result,
                "Current state returned immediately without changing environment or "
                "deployment state."
                if fast_ok
                else "Fast-path check failed or changed environment/state.",
                duration=fast_duration,
            )
        )
        if not fast_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        scenarios = runtime_root / "scenarios"
        scenarios.mkdir(exist_ok=True)
        scenario_values = [
            (
                "state-missing",
                {
                    "runtime_paths": {
                        **manifest.runtime_paths.model_dump(),
                        "state_path": manifest.runtime_paths.state_path + "-missing",
                    }
                },
            ),
            (
                "environment-python-missing",
                {
                    "runtime_paths": {
                        **manifest.runtime_paths.model_dump(),
                        "environment_path": (
                            manifest.runtime_paths.environment_path + "-missing"
                        ),
                    }
                },
            ),
            ("deployment-fingerprint", {"deployment_fingerprint": "0" * 64}),
            ("selected-extras-fingerprint", {"selected_extras_fingerprint": "0" * 64}),
        ]
        if manifest.application_artifact is not None:
            scenario_values.append(
                (
                    "application-artifact-fingerprint",
                    {
                        "application_artifact": {
                            **manifest.application_artifact.model_dump(mode="json"),
                            "sha256": "0" * 64,
                        }
                    },
                )
            )
        stale_failures: list[str] = []
        for sequence, (name, changes) in enumerate(scenario_values, start=1):
            scenario = _scenario_copy(
                root,
                scenarios / f"{sequence:02d}-{name}-{time.time_ns()}",
                manifest,
                changes,
            )
            result, _duration = _run(
                [
                    str(app_python),
                    *HELPER_FLAGS,
                    str(scenario / "deployment" / "runtime" / "manage.py"),
                    "check",
                    "--project-root",
                    str(scenario),
                ],
                cwd=scenario,
                environment=environment,
                log_handle=log,
            )
            if result.returncode != SETUP_REQUIRED:
                stale_failures.append(f"{name}: exit {result.returncode}")
        lock_scenario = _scenario_copy(
            root,
            scenarios / f"{len(scenario_values) + 1:02d}-lock-fingerprint-{time.time_ns()}",
            manifest,
            {},
        )
        with (lock_scenario / "uv.lock").open("a", encoding="utf-8") as handle:
            handle.write("\n# controlled validation staleness\n")
        lock_result, _duration = _run(
            [
                str(app_python),
                *HELPER_FLAGS,
                str(lock_scenario / "deployment" / "runtime" / "manage.py"),
                "check",
                "--project-root",
                str(lock_scenario),
            ],
            cwd=lock_scenario,
            environment=environment,
            log_handle=log,
        )
        if lock_result.returncode != SETUP_REQUIRED:
            stale_failures.append(f"lock-fingerprint: exit {lock_result.returncode}")
        stale_subjects = "deployment and extras"
        if manifest.application_artifact is not None:
            stale_subjects += ", application artifact"
        report.runtime_checks.append(
            _check(
                "CONTROLLED_STALENESS",
                "staleness",
                ValidationCheckStatus.PASS
                if not stale_failures
                else ValidationCheckStatus.FAIL,
                f"Missing state/Python and changed {stale_subjects}, and lock fingerprints "
                "all request setup."
                if not stale_failures
                else "A controlled stale state did not request setup.",
                evidence=stale_failures,
            )
        )
        if stale_failures:
            report.final_state = ValidationFinalState.FAILED
            return report

        rollback_scenario = _scenario_copy(
            root,
            scenarios / f"{len(scenario_values) + 2:02d}-rollback-{time.time_ns()}",
            manifest,
            {
                "bundled_uv_sha256": None,
                "sync_arguments": [
                    *manifest.sync_arguments,
                    "--pdbuilder-controlled-invalid-option",
                ],
            },
        )
        state_before_rollback = state_file.read_bytes()
        rollback, _duration = _run(
            [
                str(app_python),
                *HELPER_FLAGS,
                str(rollback_scenario / "deployment" / "runtime" / "manage.py"),
                "setup",
                "--project-root",
                str(rollback_scenario),
                "--uv",
                str(uv),
            ],
            cwd=rollback_scenario,
            environment=environment,
            log_handle=log,
        )
        rollback_ok = (
            rollback.returncode != 0
            and app_python.is_file()
            and state_file.read_bytes() == state_before_rollback
            and not (app_root / "env.previous").exists()
            and not (app_root / "env.failed").exists()
        )
        report.rollback_result = (
            ValidationCheckStatus.PASS if rollback_ok else ValidationCheckStatus.FAIL
        )
        report.runtime_checks.append(
            _check(
                "ROLLBACK_RESTORES_ENVIRONMENT",
                "rollback",
                report.rollback_result,
                "A controlled sync failure restored the prior environment and did not write "
                "false state."
                if rollback_ok
                else "Rollback did not restore the prior working environment cleanly.",
                evidence=[rollback.stderr[-1000:]],
            )
        )
        if not rollback_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        unrelated = local_app_data / "PythonDeploymentBuilder" / "apps" / "unrelated-app"
        unrelated.mkdir(parents=True, exist_ok=True)
        unrelated_marker = unrelated / "preserve.txt"
        unrelated_marker.write_text("preserve", encoding="utf-8")
        shared_marker = local_app_data / "PythonDeploymentBuilder" / "cache" / "preserve.txt"
        shared_marker.parent.mkdir(parents=True, exist_ok=True)
        shared_marker.write_text("preserve", encoding="utf-8")
        source_hash = hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest()
        repair_bat = _find_bat(root, "Repair ")
        repair, repair_duration = _run(
            ["cmd.exe", "/d", "/c", str(repair_bat)],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        repair_ok = (
            repair.returncode == 0
            and app_python.is_file()
            and state_file.is_file()
            and unrelated_marker.read_text(encoding="utf-8") == "preserve"
            and shared_marker.read_text(encoding="utf-8") == "preserve"
            and hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest()
            == source_hash
        )
        report.repair_result = (
            ValidationCheckStatus.PASS if repair_ok else ValidationCheckStatus.FAIL
        )
        report.runtime_checks.append(
            _check(
                "REPAIR_SCOPE",
                "repair",
                report.repair_result,
                "Repair rebuilt only this app environment and preserved source, shared cache, "
                "and an unrelated app."
                if repair_ok
                else "Repair failed or changed data outside this app environment/state.",
                evidence=[repair.stderr[-1000:]],
                duration=repair_duration,
            )
        )
        if not repair_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        healthy, healthy_duration = _run(
            ["cmd.exe", "/d", "/c", str(diagnose_bat)],
            cwd=root,
            environment=environment,
            log_handle=log,
        )
        broken_local = runtime_root / "BrokenLocalAppData"
        broken_state = _expand(manifest.runtime_paths.state_path, broken_local)
        broken_state.mkdir(parents=True, exist_ok=True)
        shutil.copy2(state_file, broken_state / state_file.name)
        broken_environment = _runtime_environment(manifest, broken_local)
        broken, broken_duration = _run(
            ["cmd.exe", "/d", "/c", str(diagnose_bat)],
            cwd=root,
            environment=broken_environment,
            log_handle=log,
        )
        diagnostics_ok = (
            healthy.returncode == 0
            and broken.returncode == 0
            and "Environment state: current" in healthy.stdout
            and "Managed application Python is unavailable" in broken.stdout
            and all(
                value not in healthy.stdout + broken.stdout
                for name in manifest.configuration_secret_names
                if (value := os.environ.get(name))
            )
        )
        report.diagnostics_result = (
            ValidationCheckStatus.PASS if diagnostics_ok else ValidationCheckStatus.FAIL
        )
        report.runtime_checks.append(
            _check(
                "DIAGNOSTICS_HEALTHY_AND_BROKEN",
                "diagnostics",
                report.diagnostics_result,
                "Diagnose BAT remained useful before setup, when healthy, and with a missing "
                "environment."
                if diagnostics_ok
                else "Diagnostics did not correctly cover healthy and broken states.",
                evidence=[healthy.stdout[-1000:], broken.stdout[-1000:]],
                duration=healthy_duration + broken_duration,
            )
        )
        if not diagnostics_ok:
            report.final_state = ValidationFinalState.FAILED
            return report

        report.external_runtimes = [
            ExternalRuntimeValidation(
                name=item.name,
                feature=item.feature,
                status="not_checked",
                detail=(
                    "Generated diagnostics perform the planned non-destructive detection; "
                    "manual feature validation remains required."
                ),
            )
            for item in manifest.external_runtimes
        ]
        app_logs = _expand(manifest.runtime_paths.logs_path, local_app_data)
        if app_logs.is_dir():
            report.log_paths.extend(str(path) for path in sorted(app_logs.glob("*.log")))

    report.final_state = (
        ValidationFinalState.MANUAL_GUI_VALIDATION_REQUIRED
        if manifest.entry_point_kind == "gui"
        else ValidationFinalState.RUNTIME_VALIDATED
    )
    return report


__all__ = ["HELPER_FLAGS", "validate_runtime_kit"]
