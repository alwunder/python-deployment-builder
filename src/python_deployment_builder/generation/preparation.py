"""Explicit developer-side lockfile preparation and verification."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.security import redact_secrets
from python_deployment_builder.models import DeploymentPlan


@dataclass(frozen=True)
class LockPreparationResult:
    path: Path
    created: bool
    checked: bool
    commands: tuple[tuple[str, ...], ...]


def _sanitized_failure(result: subprocess.CompletedProcess[str]) -> str:
    text = (result.stderr or result.stdout or "No command output was produced.").strip()
    return redact_secrets(text[-3000:])


def prepare_lockfile(
    repository_root: Path,
    plan: DeploymentPlan,
    uv_executable: Path,
    *,
    allow_create: bool,
    system_certs: bool,
    runner=subprocess.run,
) -> LockPreparationResult:
    """Create a missing lock only with authorization, then prove it is current."""

    repository_root = repository_root.resolve()
    lockfile = repository_root / "uv.lock"
    commands: list[tuple[str, ...]] = []
    environment = os.environ.copy()
    environment.update(
        {
            "UV_MANAGED_PYTHON": "1",
            "UV_NO_PROGRESS": "1",
            "UV_NO_ENV_FILE": "1",
        }
    )
    if system_certs:
        environment["UV_SYSTEM_CERTS"] = "true"

    def run(arguments: list[str]) -> None:
        command = [str(uv_executable), *arguments]
        commands.append(tuple(command))
        try:
            result = runner(
                command,
                cwd=repository_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreparationError(f"Pinned uv lock preparation could not run: {exc}") from exc
        if result.returncode != 0:
            raise PreparationError(
                f"Pinned uv command failed ({' '.join(arguments)}): "
                f"{_sanitized_failure(result)}"
            )

    created = False
    if not lockfile.is_file():
        if not allow_create:
            raise PreparationError(
                "uv.lock is missing. Re-run generation with --prepare-lock for a local "
                "repository to authorize developer-side lockfile creation."
            )
        run(["lock", "--python", plan.runtime.python_version])
        created = True
        if not lockfile.is_file():
            raise PreparationError("Pinned uv reported success but did not create uv.lock.")

    run(["lock", "--check", "--python", plan.runtime.python_version])
    return LockPreparationResult(
        path=lockfile,
        created=created,
        checked=True,
        commands=tuple(commands),
    )
