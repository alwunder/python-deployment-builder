"""Evidence-driven human smoke-test handoff generation."""

from __future__ import annotations

from python_deployment_builder.models import DeploymentManifest


def render_smoke_test(manifest: DeploymentManifest, zip_filename: str) -> str:
    display = manifest.application_display_name
    lines = [
        f"{display.upper()} - WINDOWS STANDARD USER SMOKE TEST",
        "",
        f"Package: {zip_filename}",
        "",
        "This is a human acceptance handoff. Python Deployment Builder has validated package",
        "structure and deployment behavior; it cannot infer every application-specific result.",
        "",
        "PRECONDITIONS",
        "-------------",
        "1. Use a Windows Standard User account.",
        "2. Extract the ZIP into a new user-writable folder.",
        "3. Do not run the application from inside the ZIP.",
        "4. Do not run as Administrator or manually install/configure Python.",
        "5. Do not use PowerShell or bypass organizational security policy.",
        "",
        "FIRST LAUNCH",
        "------------",
        f"1. Double-click Run {display}.bat.",
        "2. Confirm no elevation prompt appears.",
        "3. Confirm first-run setup completes and the application opens or runs.",
        "4. [MANUAL] Exercise one representative core application workflow.",
    ]
    if manifest.project_write_probe_required:
        lines.append("5. Confirm the application can write its planned project/output location.")
    if manifest.configuration_presence_names:
        names = ", ".join(manifest.configuration_presence_names)
        lines.extend(
            [
                "",
                "CONFIGURATION",
                "-------------",
                f"- Relevant configuration presence checks: {names}.",
                "- Use the application's intended configuration workflow; never put secret "
                "values in the test report or deployment logs.",
            ]
        )
    if manifest.external_runtimes:
        lines.extend(
            ["", "SELECTED FEATURES / EXTERNAL RUNTIMES", "-------------------------------------"]
        )
        for runtime in manifest.external_runtimes:
            feature = runtime.feature or "core"
            lines.append(
                f"- Confirm Diagnose reports {runtime.name}; [MANUAL] exercise the "
                f"'{feature}' feature that depends on it."
            )
    lines.extend(
        [
            "",
            "FAST PATH",
            "---------",
            "1. Close the application.",
            f"2. Double-click Run {display}.bat again.",
            "3. Confirm launch is materially faster and no Python reinstall, dependency sync, "
            "or environment rebuild occurs.",
            "",
            "DIAGNOSTICS",
            "-----------",
            f"1. Double-click Diagnose {display}.bat.",
            "2. Confirm the environment state is current.",
            "3. Confirm the most recent application launch failure is none recorded.",
        ]
    )
    if manifest.selected_extras:
        lines.append(f"4. Confirm selected extras include: {', '.join(manifest.selected_extras)}.")
    if manifest.approved_artifacts:
        artifacts = ", ".join(
            f"{item.distribution_name}=={item.version}" for item in manifest.approved_artifacts
        )
        lines.append(f"5. Confirm approved artifacts include: {artifacts}.")
    lines.extend(
        [
            "",
            "RESULT",
            "------",
            "No elevation requested: yes / no",
            "Application opened/ran: yes / no",
            "Representative core workflow passed: yes / no",
            "Selected feature/external runtime checks passed: yes / no / not applicable",
            "Fast relaunch passed: yes / no",
            "Diagnose current/no launch failure: yes / no",
            "",
            "Problems/comments:",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = ["render_smoke_test"]
