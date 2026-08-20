"""Explicit networked developer acceptance test for pinned uv 0.12.5."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from python_deployment_builder.backends.uv_managed import UvManagedBackend
from python_deployment_builder.generation.acquisition import acquire_pinned_uv


def _record_digest(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode('ascii')}"


def create_proxy_tools_wheel(destination: Path) -> Path:
    wheel = destination / "proxy_tools-0.1.0-py3-none-any.whl"
    files = {
        "proxy_tools/__init__.py": b'__version__ = "0.1.0"\n',
        "proxy_tools-0.1.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: proxy-tools\nVersion: 0.1.0\n\n"
        ),
        "proxy_tools-0.1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: pdbuilder-acceptance\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in files.items():
        writer.writerow((name, _record_digest(data), len(data)))
    record_name = "proxy_tools-0.1.0.dist-info/RECORD"
    writer.writerow((record_name, "", ""))
    files[record_name] = record.getvalue().encode("utf-8")
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr(name, data)
    return wheel


def run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({subprocess.list2cmdline(command)}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout.strip()


def installed_version(python: Path, environment: dict[str, str]) -> str | None:
    result = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import importlib.metadata as m; print(m.version('proxy-tools'))",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    runtime = UvManagedBackend().build_plan(
        "uv-0125-acceptance",
        "3.12",
        "x86_64",
        deployment_mode="source",
        source_roots=["."],
        selected_extras=["map"],
    )
    uv = acquire_pinned_uv(runtime.bootstrap_artifact)
    with tempfile.TemporaryDirectory(prefix="pdbuilder-uv-0125-") as raw:
        root = Path(raw)
        project = root / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            """[project]
name = "pdbuilder-uv-acceptance"
version = "0.0.0"
requires-python = ">=3.12"
dependencies = []

[project.optional-dependencies]
map = ["proxy-tools==0.1.0"]

[dependency-groups]
dev = ["typing-extensions"]
""",
            encoding="utf-8",
        )
        wheel = create_proxy_tools_wheel(root)
        python_root = root / "python"
        environment_path = root / "application-env"
        environment = os.environ.copy()
        environment.update(
            {
                "UV_CACHE_DIR": str(root / "cache"),
                "UV_PROJECT_ENVIRONMENT": str(environment_path),
                "UV_PYTHON_INSTALL_DIR": str(python_root),
                "UV_MANAGED_PYTHON": "1",
                "UV_NO_PROGRESS": "1",
                "UV_NO_ENV_FILE": "1",
                "UV_SYSTEM_CERTS": "true",
            }
        )
        run(
            [
                str(uv),
                "python",
                "install",
                "3.12",
                "--install-dir",
                str(python_root),
                "--no-bin",
                "--no-registry",
                "--managed-python",
            ],
            cwd=project,
            environment=environment,
        )
        run([str(uv), "lock", "--python", "3.12"], cwd=project, environment=environment)
        run(
            [str(uv), "lock", "--check", "--python", "3.12"],
            cwd=project,
            environment=environment,
        )
        sync = [
            str(uv),
            "sync",
            "--locked",
            "--no-build",
            "--managed-python",
            "--python",
            "3.12",
            "--no-dev",
            "--extra",
            "map",
            "--no-install-project",
            "--no-install-package",
            "proxy-tools",
        ]
        run(sync, cwd=project, environment=environment)
        python = environment_path / "Scripts" / "python.exe"
        if (project / ".venv").exists() or not python.is_file():
            raise RuntimeError(
                "UV_PROJECT_ENVIRONMENT did not isolate the application environment."
            )
        install = [
            str(uv),
            "pip",
            "install",
            "--python",
            str(python),
            "--no-deps",
            "--no-build",
            str(wheel),
        ]
        run(install, cwd=project, environment=environment)
        if installed_version(python, environment) != "0.1.0":
            raise RuntimeError("Approved wheel was not installed at its exact version.")
        run(sync, cwd=project, environment=environment)
        removed_by_exact_sync = installed_version(python, environment) is None
        run(install, cwd=project, environment=environment)
        run(
            [str(uv), "pip", "check", "--python", str(python)],
            cwd=project,
            environment=environment,
        )
        if installed_version(python, environment) != "0.1.0":
            raise RuntimeError("Approved wheel workflow did not survive a complete setup cycle.")
        print(
            json.dumps(
                {
                    "uv": run([str(uv), "--version"], cwd=project, environment=environment),
                    "python": run([str(python), "--version"], cwd=project, environment=environment),
                    "controlled_environment": str(environment_path),
                    "project_venv_created": (project / ".venv").exists(),
                    "approved_artifact_version": installed_version(python, environment),
                    "exact_sync_removed_local_wheel_before_reinstall": removed_by_exact_sync,
                    "system_certs": True,
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
