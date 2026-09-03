"""Invoke the authoritative entry point from staged source or the installed wheel."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import os
import sys
import tempfile
import traceback
from pathlib import Path

from runtime_common import (
    DeploymentRuntimeError,
    load_manifest,
    redact,
    write_application_launch_failure,
)


def configure_source_paths(manifest: dict, project_root: Path) -> None:
    if manifest.get("deployment_mode", "source") != "source":
        return
    for relative in reversed(manifest["source_roots"]):
        path = project_root if relative == "." else project_root / relative
        sys.path.insert(0, str(path.resolve()))


def check_entry_point(manifest: dict, project_root: Path) -> None:
    configure_source_paths(manifest, project_root)
    if importlib.util.find_spec(manifest["entry_point_module"]) is None:
        raise DeploymentRuntimeError(
            f"Entry-point module is not importable: {manifest['entry_point_module']}"
        )
    module = importlib.import_module(manifest["entry_point_module"])
    target = getattr(module, manifest["entry_point_callable"], None)
    if not callable(target):
        raise DeploymentRuntimeError(
            "Entry-point callable is unavailable: "
            f"{manifest['entry_point_module']}:{manifest['entry_point_callable']}"
        )
    if manifest.get("project_write_probe_required"):
        probe_project_write(project_root, manifest["application_display_name"])


def probe_project_write(project_root: Path, display_name: str) -> None:
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=".pdbuilder-write-probe-", dir=project_root)
        os.close(descriptor)
        Path(raw_path).unlink()
    except OSError as exc:
        raise DeploymentRuntimeError(
            f"{display_name} cannot write to this extracted folder.\n\n"
            "Move or extract the application to a folder you can write to, such as a folder "
            "under your user profile. Administrator privileges are not required or requested."
        ) from exc


def invoke(manifest: dict, project_root: Path) -> int:
    configure_source_paths(manifest, project_root)
    os.chdir(project_root)
    if manifest.get("project_write_probe_required"):
        probe_project_write(project_root, manifest["application_display_name"])
    module = importlib.import_module(manifest["entry_point_module"])
    target = getattr(module, manifest["entry_point_callable"])
    original_argv = sys.argv[:]
    try:
        # Helper arguments are private deployment details. Application arguments are
        # intentionally empty for the current launcher contract.
        sys.argv = [manifest.get("entry_point_name") or manifest["entry_point_module"]]
        result = target()
    finally:
        sys.argv = original_argv
    return result if isinstance(result, int) else 0


def _system_exit_code(value: object) -> int:
    if value is None:
        return 0
    return value if isinstance(value, int) else 1


def _record_failure(manifest: dict, summary: str, details: str) -> Path | None:
    try:
        return write_application_launch_failure(manifest, summary, details)
    except OSError:
        return None


def _report_failure(summary: str, log_path: Path | None) -> None:
    if sys.stderr is None:
        return
    print(f"Application launch failed: {redact(summary)}", file=sys.stderr)
    if log_path is not None:
        print(f"Application launch failure log: {log_path}", file=sys.stderr)


def invoke_with_failure_logging(manifest: dict, project_root: Path) -> int:
    try:
        result = invoke(manifest, project_root)
    except SystemExit as exc:
        exit_code = _system_exit_code(exc.code)
        if exit_code == 0:
            return 0
        summary = f"Entry point exited with SystemExit code {exit_code}."
        log_path = _record_failure(manifest, summary, traceback.format_exc())
        _report_failure(summary, log_path)
        return exit_code
    except Exception as exc:
        summary = f"{type(exc).__name__}: {exc}"
        log_path = _record_failure(manifest, summary, traceback.format_exc())
        _report_failure(summary, log_path)
        return 1
    if result != 0:
        summary = f"Entry point returned non-zero exit code {result}."
        log_path = _record_failure(manifest, summary, "No Python exception was raised.")
        _report_failure(summary, log_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    manifest = load_manifest()
    project_root = arguments.project_root.resolve()
    if arguments.check:
        try:
            check_entry_point(manifest, project_root)
            return 0
        except (DeploymentRuntimeError, ImportError, AttributeError, OSError) as exc:
            if sys.stderr is not None:
                print(f"Application launch failed: {exc}", file=sys.stderr)
            return 1
    return invoke_with_failure_logging(manifest, project_root)


if __name__ == "__main__":
    raise SystemExit(main())
