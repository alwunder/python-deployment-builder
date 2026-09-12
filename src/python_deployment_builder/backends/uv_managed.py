"""Windows, pinned-uv, per-user managed CPython runtime policy."""

from __future__ import annotations

from collections.abc import Sequence

from python_deployment_builder.models import (
    BootstrapArtifact,
    PlannedCommand,
    RuntimePaths,
    RuntimePlan,
)

UV_VERSION = "0.12.5"
UV_RELEASE_BASE = f"https://releases.astral.sh/github/uv/releases/download/{UV_VERSION}"
UV_ARTIFACTS = {
    "x86_64": (
        "uv-x86_64-pc-windows-msvc.zip",
        "4c4d49d8738847d9b71ba319e49a5688c93eac0fe6204b1df24e98528dddf39a",
    ),
    "arm64": (
        "uv-aarch64-pc-windows-msvc.zip",
        "724279317fee6e5fa8ad1908e4eba2bbe764ef1ece5b3f4597927b62b1fe562a",
    ),
}


def uv_sync_arguments(
    *,
    python_version: str,
    selected_extras: Sequence[str],
    approved_artifact_names: Sequence[str] = (),
) -> list[str]:
    """Return the exact immutable uv sync command accepted by the M6.1 runtime."""

    arguments = [
        "sync",
        "--locked",
        "--no-build",
        "--managed-python",
        "--python",
        python_version,
    ]
    if "dev" not in selected_extras:
        arguments.append("--no-dev")
    for extra in selected_extras:
        arguments.extend(["--extra", extra])
    arguments.append("--no-install-project")
    for distribution_name in approved_artifact_names:
        arguments.extend(["--no-install-package", distribution_name])
    return arguments


class UvManagedBackend:
    """Plan exact LocalAppData paths and commands for the first runtime backend."""

    name = "uv_managed"

    def build_plan(
        self,
        application_id: str,
        python_version: str,
        architecture: str,
        *,
        deployment_mode: str = "package",
        source_roots: list[str] | None = None,
        selected_extras: list[str] | None = None,
    ) -> RuntimePlan:
        if architecture not in UV_ARTIFACTS:
            raise ValueError(f"Unsupported Windows architecture: {architecture}")

        archive, sha256 = UV_ARTIFACTS[architecture]
        shared = r"%LOCALAPPDATA%\PythonDeploymentBuilder"
        app_root = rf"{shared}\apps\{application_id}"
        paths = RuntimePaths(
            shared_root=shared,
            uv_executable=rf"{shared}\tools\uv\{UV_VERSION}\uv.exe",
            python_install_root=rf"{shared}\python",
            cache_root=rf"{shared}\cache\uv",
            application_root=app_root,
            environment_path=rf"{app_root}\env",
            logs_path=rf"{app_root}\logs",
            state_path=rf"{app_root}\state",
        )
        environment = {
            "UV_CACHE_DIR": paths.cache_root,
            "UV_MANAGED_PYTHON": "1",
            "UV_NO_PROGRESS": "1",
            "UV_PROJECT_ENVIRONMENT": paths.environment_path,
            "UV_PYTHON_INSTALL_BIN": "0",
            "UV_PYTHON_INSTALL_DIR": paths.python_install_root,
            "UV_PYTHON_INSTALL_REGISTRY": "0",
            "UV_PYTHON_NO_REGISTRY": "1",
        }
        if deployment_mode == "source":
            roots = source_roots or ["."]
            environment["PYTHONPATH"] = ";".join(
                "%PROJECT_ROOT%" if root == "." else rf"%PROJECT_ROOT%\{root}"
                for root in roots
            )
        provision = PlannedCommand(
            executable=paths.uv_executable,
            arguments=[
                "python",
                "install",
                python_version,
                "--install-dir",
                paths.python_install_root,
                "--no-bin",
                "--no-registry",
                "--managed-python",
            ],
            purpose="Install the selected managed CPython without PATH or registry integration.",
        )
        selected_extras = selected_extras or []
        sync_arguments = uv_sync_arguments(
            python_version=python_version,
            selected_extras=selected_extras,
        )
        sync = PlannedCommand(
            executable=paths.uv_executable,
            arguments=sync_arguments,
            working_directory="%PROJECT_ROOT%",
            purpose=(
                "Synchronize dependencies from the committed lockfile without installing the "
                "source-based project."
                if deployment_mode == "source"
                else "Synchronize the per-application environment from the committed lockfile."
            ),
        )
        application_install = None
        if deployment_mode != "source":
            application_install = PlannedCommand(
                executable=paths.uv_executable,
                arguments=[
                    "pip",
                    "install",
                    "--python",
                    rf"{paths.environment_path}\Scripts\python.exe",
                    "--no-deps",
                    "--no-build",
                    "%APPLICATION_WHEEL%",
                ],
                working_directory="%PROJECT_ROOT%",
                purpose=(
                    "Install the developer-built application wheel without resolving or building "
                    "dependencies."
                ),
            )
        return RuntimePlan(
            backend="uv_managed",
            architecture=architecture,
            python_version=python_version,
            uv_version=UV_VERSION,
            bootstrap_artifact=BootstrapArtifact(
                version=UV_VERSION,
                architecture=architecture,
                url=f"{UV_RELEASE_BASE}/{archive}",
                sha256=sha256,
            ),
            paths=paths,
            environment_variables=environment,
            provision_command=provision,
            sync_command=sync,
            application_install_command=application_install,
            launch_executable=rf"{paths.environment_path}\Scripts\pythonw.exe",
            selected_extras=selected_extras,
        )
