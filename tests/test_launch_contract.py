from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from python_deployment_builder.generation.templates import TEMPLATE_ROOT


def _write_launch_fixture(
    tmp_path: Path, target_source: str, *, callable_name: str = "main"
) -> tuple[Path, Path, Path]:
    project_root = tmp_path / "application"
    project_root.mkdir()
    (project_root / "synthetic_target.py").write_text(dedent(target_source), encoding="utf-8")
    (project_root / "pyproject.toml").write_text("[project]\nname='synthetic'\n", encoding="utf-8")
    (project_root / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    deployment = project_root / "deployment"
    runtime = deployment / "runtime"
    runtime.mkdir(parents=True)
    for name in ("runtime_common.py", "launch.py", "diagnostics.py"):
        shutil.copy2(TEMPLATE_ROOT / name, runtime / name)

    local_app_data = tmp_path / "LocalAppData"
    manifest = {
        "application_id": "synthetic-app",
        "application_display_name": "Synthetic Application",
        "entry_point_name": "synthetic-entry",
        "entry_point_kind": "gui",
        "entry_point_module": "synthetic_target",
        "entry_point_callable": callable_name,
        "deployment_mode": "source",
        "source_roots": ["."],
        "project_write_probe_required": False,
        "schema_version": "1.0",
        "deployment_fingerprint": "synthetic-fingerprint",
        "uv_version": "0.12.5",
        "python_version": "3.12",
        "pyproject_sha256": "synthetic-pyproject-hash",
        "lockfile_sha256": "synthetic-lock-hash",
        "selected_extras_fingerprint": "synthetic-extras-hash",
        "selected_extras": [],
        "approved_artifacts": [],
        "configuration_presence_names": [],
        "external_runtimes": [],
        "bootstrap_mode": "bundled_uv",
        "system_certs": True,
        "runtime_paths": {
            "application_root": (
                r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\synthetic-app"
            ),
            "environment_path": (
                r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\synthetic-app\env"
            ),
            "logs_path": (
                r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\synthetic-app\logs"
            ),
            "state_path": (
                r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\synthetic-app\state"
            ),
        },
    }
    (deployment / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return project_root, runtime / "launch.py", local_app_data


def _run_launch(
    project_root: Path, launcher: Path, local_app_data: Path
) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    environment["PYTHONPATH"] = str(project_root / "must-be-ignored")
    return subprocess.run(
        [
            sys.executable,
            "-B",
            "-E",
            "-s",
            str(launcher),
            "--project-root",
            str(project_root),
        ],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _run_diagnostics(
    project_root: Path, launcher: Path, local_app_data: Path
) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    return subprocess.run(
        [
            sys.executable,
            "-B",
            "-E",
            "-s",
            str(launcher.with_name("diagnostics.py")),
            "--project-root",
            str(project_root),
        ],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _failure_logs(local_app_data: Path) -> list[Path]:
    directory = (
        local_app_data / "PythonDeploymentBuilder" / "apps" / "synthetic-app" / "logs"
    )
    return sorted(directory.glob("application-launch-failure-*.log"))


def test_generated_launch_isolates_application_argv_in_real_subprocess(tmp_path: Path) -> None:
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path,
        """
        import argparse
        import atexit
        import json
        import sys
        from pathlib import Path

        def main():
            parser = argparse.ArgumentParser()
            parser.parse_args()
            Path("target-invoked.txt").write_text("yes", encoding="utf-8")
            Path("argv-during.json").write_text(json.dumps(sys.argv), encoding="utf-8")
            atexit.register(
                lambda: Path("argv-after.json").write_text(
                    json.dumps(sys.argv), encoding="utf-8"
                )
            )
        """,
    )

    result = _run_launch(project_root, launcher, local_app_data)

    assert result.returncode == 0, result.stderr
    assert (project_root / "target-invoked.txt").read_text(encoding="utf-8") == "yes"
    assert json.loads((project_root / "argv-during.json").read_text(encoding="utf-8")) == [
        "synthetic-entry"
    ]
    restored = json.loads((project_root / "argv-after.json").read_text(encoding="utf-8"))
    assert restored[0] == str(launcher)
    assert restored[1:] == ["--project-root", str(project_root)]
    assert not _failure_logs(local_app_data)


def test_generated_launch_keeps_geo_style_no_arg_callable_working(tmp_path: Path) -> None:
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path,
        """
        from pathlib import Path

        def main():
            Path("geo-style-called.txt").write_text("yes", encoding="utf-8")
        """,
    )

    result = _run_launch(project_root, launcher, local_app_data)

    assert result.returncode == 0, result.stderr
    assert (project_root / "geo-style-called.txt").is_file()
    assert not _failure_logs(local_app_data)


def test_generated_launch_resolves_qualified_entry_point_object_in_source_and_package_modes(
    tmp_path: Path,
) -> None:
    target_source = """
        from pathlib import Path

        class Runner:
            @staticmethod
            def main():
                Path("qualified-target-called.txt").write_text("yes", encoding="utf-8")
    """
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path, target_source, callable_name="Runner.main"
    )

    source_result = _run_launch(project_root, launcher, local_app_data)

    assert source_result.returncode == 0, source_result.stderr
    assert (project_root / "qualified-target-called.txt").is_file()
    (project_root / "qualified-target-called.txt").unlink()
    (launcher.parent / "synthetic_target.py").write_text(
        dedent(target_source), encoding="utf-8"
    )
    manifest_path = project_root / "deployment/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["deployment_mode"] = "package"
    manifest["source_roots"] = []
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    package_result = _run_launch(project_root, launcher, local_app_data)

    assert package_result.returncode == 0, package_result.stderr
    assert (project_root / "qualified-target-called.txt").is_file()


@pytest.mark.parametrize(
    ("statement", "expected_code", "failure_expected"),
    [
        ("return 0", 0, False),
        ("return 7", 7, True),
        ("raise SystemExit(0)", 0, False),
        ("raise SystemExit(6)", 6, True),
    ],
)
def test_generated_launch_return_and_system_exit_semantics(
    tmp_path: Path,
    statement: str,
    expected_code: int,
    failure_expected: bool,
) -> None:
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path,
        f"""
        def main():
            {statement}
        """,
    )

    result = _run_launch(project_root, launcher, local_app_data)

    assert result.returncode == expected_code
    logs = _failure_logs(local_app_data)
    assert bool(logs) is failure_expected
    if failure_expected:
        assert str(expected_code) in logs[-1].read_text(encoding="utf-8")


def test_generated_launch_logs_and_redacts_ordinary_exception(tmp_path: Path) -> None:
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path,
        """
        def main():
            raise RuntimeError("api_key=supersecret")
        """,
    )

    result = _run_launch(project_root, launcher, local_app_data)

    assert result.returncode == 1
    logs = _failure_logs(local_app_data)
    assert len(logs) == 1
    content = logs[0].read_text(encoding="utf-8")
    assert "RuntimeError" in content
    assert "Traceback" in content
    assert "[REDACTED]" in content
    assert "supersecret" not in content
    assert str(logs[0]) in result.stderr

    diagnostics = _run_diagnostics(project_root, launcher, local_app_data)
    assert diagnostics.returncode == 0, diagnostics.stderr
    assert f"Most recent application launch failure: {logs[0]}" in diagnostics.stdout


def test_package_launch_does_not_import_same_named_module_from_repository_cwd(
    tmp_path: Path,
) -> None:
    project_root, launcher, local_app_data = _write_launch_fixture(
        tmp_path,
        """
        from pathlib import Path
        Path("source-sentinel.txt").write_text("source", encoding="utf-8")
        def main(): return 0
        """,
    )
    (launcher.parent / "synthetic_target.py").write_text(
        "from pathlib import Path\n"
        "Path('installed-sentinel.txt').write_text('installed', encoding='utf-8')\n"
        "def main(): return 0\n",
        encoding="utf-8",
    )
    manifest_path = project_root / "deployment/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["deployment_mode"] = "package"
    manifest["source_roots"] = []
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = _run_launch(project_root, launcher, local_app_data)

    assert result.returncode == 0, result.stderr
    assert (project_root / "installed-sentinel.txt").read_text(encoding="utf-8") == "installed"
    assert not (project_root / "source-sentinel.txt").exists()
