"""PowerShell-free Windows bootstrap capability policy."""

from python_deployment_builder.models import (
    BootstrapHostTool,
    BootstrapModePlan,
    BootstrapPlan,
    ShellPolicy,
)


def windows_shell_policy() -> ShellPolicy:
    return ShellPolicy()


def windows_bootstrap_plan() -> BootstrapPlan:
    online_tools = [
        BootstrapHostTool(
            executable="curl.exe",
            purpose="Download the pinned official uv archive over HTTPS.",
        ),
        BootstrapHostTool(
            executable="certutil.exe",
            purpose="Calculate SHA-256 for comparison with pinned deployment metadata.",
        ),
        BootstrapHostTool(
            executable="tar.exe",
            purpose="Extract the checksum-verified uv ZIP archive.",
        ),
    ]
    return BootstrapPlan(
        preferred_mode="bundled_uv",
        modes=[
            BootstrapModePlan(
                mode="bundled_uv",
                status="supported",
                requires_network=False,
                description=(
                    "Use a developer-verified pinned uv.exe included in the generated kit."
                ),
            ),
            BootstrapModePlan(
                mode="online_cmd",
                status="supported",
                requires_network=True,
                required_host_tools=online_tools,
                description=(
                    "Use cmd.exe plus explicitly preflighted native Windows tools; no shell "
                    "substitution is permitted."
                ),
            ),
            BootstrapModePlan(
                mode="offline_bundle",
                status="future",
                requires_network=False,
                description="Future bundle containing uv, managed Python, and approved artifacts.",
            ),
        ],
        unavailable_policy=(
            "If HTTPS or a required native executable is missing or policy-blocked, online_cmd is "
            "unavailable; require bundled_uv or a future offline bundle without bypassing policy."
        ),
    )
