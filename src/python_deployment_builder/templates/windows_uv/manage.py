"""Per-user setup, stale-state handling, repair, and fast launch."""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from runtime_common import (
    DeploymentRuntimeError,
    application_root,
    deployment_directory,
    environment_path,
    guarded_environment_path,
    load_manifest,
    logs_path,
    redact,
    runtime_environment,
    safe_remove_environment,
    stale_reasons,
    state_path,
    verify_runtime_inputs,
    write_state,
)

SETUP_REQUIRED = 20


def configure_logging(manifest: dict) -> tuple[logging.Logger, Path]:
    directory = logs_path(manifest)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"deployment-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.log"
    logger = logging.getLogger("deployment")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger, path


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    logger: logging.Logger,
) -> None:
    logger.info("Command: %s", redact(subprocess.list2cmdline(command)))
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        logger.info("stdout:\n%s", redact(result.stdout.rstrip()))
    if result.stderr:
        logger.info("stderr:\n%s", redact(result.stderr.rstrip()))
    logger.info("Exit code: %s", result.returncode)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "No command output was produced.").strip()
        raise DeploymentRuntimeError(redact(detail[-2000:]))


def verify_uv(uv_executable: Path, manifest: dict, logger: logging.Logger) -> None:
    result = subprocess.run(
        [str(uv_executable), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    actual = (result.stdout or result.stderr).strip()
    logger.info("uv version: %s", actual)
    fields = actual.split()
    if result.returncode != 0 or fields[:2] != ["uv", manifest["uv_version"]]:
        raise DeploymentRuntimeError(
            f"Expected uv {manifest['uv_version']}, received {actual or result.returncode}."
        )


def launch_application(manifest: dict, project_root: Path, logger: logging.Logger) -> int:
    environment = environment_path(manifest)
    executable_name = "pythonw.exe" if manifest["entry_point_kind"] == "gui" else "python.exe"
    executable = environment / "Scripts" / executable_name
    launcher = deployment_directory() / "runtime" / "launch.py"
    command = [
        str(executable),
        "-B",
        "-E",
        "-s",
        str(launcher),
        "--project-root",
        str(project_root),
    ]
    logger.info("Launch command: %s", subprocess.list2cmdline(command))
    child_environment = runtime_environment(manifest, project_root, environment)
    if manifest["entry_point_kind"] == "gui":
        subprocess.Popen(command, cwd=project_root, env=child_environment)
        return 0
    return subprocess.run(command, cwd=project_root, env=child_environment, check=False).returncode


def _promote_environment(
    manifest: dict,
    project_root: Path,
    uv_executable: Path,
    logger: logging.Logger,
) -> None:
    environment = guarded_environment_path(manifest, environment_path(manifest))
    previous = guarded_environment_path(manifest, application_root(manifest) / "env.previous")
    failed = guarded_environment_path(manifest, application_root(manifest) / "env.failed")
    safe_remove_environment(manifest, previous)
    safe_remove_environment(manifest, failed)
    if environment.exists():
        environment.replace(previous)
        logger.info("Preserved the previous environment at %s", previous)

    runtime_env = runtime_environment(manifest, project_root, environment)
    try:
        sync = [str(uv_executable), *manifest["sync_arguments"]]
        run_logged(sync, cwd=project_root, environment=runtime_env, logger=logger)
        python = environment / "Scripts" / "python.exe"
        pythonw = environment / "Scripts" / "pythonw.exe"
        if not python.is_file() or not pythonw.is_file():
            raise DeploymentRuntimeError(
                "The prepared environment is missing python.exe/pythonw.exe."
            )

        wheel_directory = deployment_directory() / "wheels"
        for artifact in manifest["approved_artifacts"]:
            wheel = wheel_directory / artifact["filename"]
            command = [
                str(uv_executable),
                "pip",
                "install",
                "--python",
                str(python),
                "--no-deps",
                "--no-build",
                str(wheel),
            ]
            run_logged(command, cwd=project_root, environment=runtime_env, logger=logger)
        application_artifact = manifest.get("application_artifact")
        if application_artifact:
            application_wheel = (
                deployment_directory() / "application" / application_artifact["filename"]
            )
            run_logged(
                [
                    str(uv_executable),
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    "--no-deps",
                    "--no-build",
                    str(application_wheel),
                ],
                cwd=project_root,
                environment=runtime_env,
                logger=logger,
            )
        run_logged(
            [str(uv_executable), "pip", "check", "--python", str(python)],
            cwd=project_root,
            environment=runtime_env,
            logger=logger,
        )

        launch_check = [
            str(python),
            "-B",
            "-E",
            "-s",
            str(deployment_directory() / "runtime" / "launch.py"),
            "--project-root",
            str(project_root),
            "--check",
        ]
        run_logged(launch_check, cwd=project_root, environment=runtime_env, logger=logger)
        write_state(manifest, project_root, datetime.now(UTC).isoformat())
    except Exception:
        if environment.exists():
            environment.replace(failed)
        if previous.exists():
            previous.replace(environment)
            logger.error("Restored the previously working environment after setup failure.")
        safe_remove_environment(manifest, failed)
        raise


def setup(
    manifest: dict,
    project_root: Path,
    uv_executable: Path,
    *,
    repair: bool,
    launch: bool,
    logger: logging.Logger,
) -> int:
    verify_runtime_inputs(manifest, project_root)
    verify_uv(uv_executable, manifest, logger)
    if repair:
        state_file = state_path(manifest) / "deployment-state.json"
        state_file.unlink(missing_ok=True)
    print("Preparing application environment...")
    _promote_environment(manifest, project_root, uv_executable, logger)
    print("Environment ready.")
    if launch:
        print(f"Opening {manifest['application_display_name']}...")
        return launch_application(manifest, project_root, logger)
    print("Repair completed successfully.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("launch", "setup", "check"))
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--uv", type=Path)
    parser.add_argument("--repair", action="store_true")
    parser.add_argument("--launch", action="store_true")
    arguments = parser.parse_args(argv)
    manifest = load_manifest()
    project_root = arguments.project_root.resolve()
    logger, log_path = configure_logging(manifest)
    try:
        if arguments.action in {"launch", "check"}:
            reasons = stale_reasons(manifest, project_root)
            if reasons:
                logger.info("Setup required: %s", "; ".join(reasons))
                return SETUP_REQUIRED
            if arguments.action == "check":
                logger.info("Fast path is current; no setup command was run.")
                return 0
            return launch_application(manifest, project_root, logger)
        if arguments.uv is None:
            raise DeploymentRuntimeError("Setup requires the exact pinned uv executable path.")
        return setup(
            manifest,
            project_root,
            arguments.uv.resolve(),
            repair=arguments.repair,
            launch=arguments.launch,
            logger=logger,
        )
    except Exception as exc:
        logger.exception("Deployment operation failed: %s", redact(str(exc)))
        print("Setup could not be completed.", file=sys.stderr)
        print(f"\nProblem:\n{redact(str(exc))}", file=sys.stderr)
        print(f"\nDiagnostic log:\n{log_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
