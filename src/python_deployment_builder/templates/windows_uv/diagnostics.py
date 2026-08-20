"""Non-destructive deployment diagnostics using only the standard library."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

from launch import probe_project_write
from runtime_common import (
    application_root,
    environment_path,
    load_manifest,
    load_state,
    sha256_file,
    stale_reasons,
)

WEBVIEW2_PRODUCT_GUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"


def _read_registry_value(hive_name: str, key_path: str, view_flag: int) -> str | None:
    try:
        import winreg
    except ImportError:
        return None
    hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view_flag) as key:
            value, _kind = winreg.QueryValueEx(key, "pv")
            return str(value)
    except OSError:
        return None


def detect_webview2(read_value=_read_registry_value) -> dict[str, object]:
    try:
        import winreg

        wow32 = winreg.KEY_WOW64_32KEY
    except ImportError:
        wow32 = 0
    locations = (
        (
            "HKLM",
            rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_PRODUCT_GUID}",
            0,
        ),
        (
            "HKLM",
            rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_PRODUCT_GUID}",
            wow32,
        ),
        (
            "HKCU",
            rf"Software\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_PRODUCT_GUID}",
            0,
        ),
    )
    for hive, path, view in locations:
        version = read_value(hive, path, view)
        if version and version.strip() and version.strip() != "0.0.0.0":
            return {"installed": True, "version": version.strip(), "location": f"{hive}\\{path}"}
    return {"installed": False, "version": None, "location": None}


def executable_observation(name: str, arguments: list[str]) -> str:
    path = shutil.which(name)
    if not path:
        return "missing"
    try:
        result = subprocess.run(
            [path, *arguments],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"present but blocked/unusable: {exc}"
    return f"available ({path}); exit code {result.returncode}"


def report(project_root: Path) -> list[str]:
    manifest = load_manifest()
    environment = environment_path(manifest)
    lines = [
        f"Application: {manifest['application_display_name']}",
        f"Windows version: {platform.platform()}",
        f"Architecture: {platform.machine()}",
        f"Username: {getpass.getuser()}",
        f"LocalAppData: {os.environ.get('LOCALAPPDATA', 'unavailable')}",
        f"Project root: {project_root}",
        f"Bootstrap mode: {manifest['bootstrap_mode']}",
        f"System certificates: {'enabled' if manifest['system_certs'] else 'disabled'}",
        f"Application runtime root: {application_root(manifest)}",
        f"Application environment: {environment}",
        f"Environment python.exe present: {(environment / 'Scripts' / 'python.exe').is_file()}",
        f"Environment pythonw.exe present: {(environment / 'Scripts' / 'pythonw.exe').is_file()}",
        f"Selected extras: {', '.join(manifest['selected_extras']) or 'none'}",
        f"Expected pyproject SHA-256: {manifest['pyproject_sha256']}",
        f"Expected uv.lock SHA-256: {manifest['lockfile_sha256']}",
    ]
    for filename, expected in (
        ("pyproject.toml", manifest["pyproject_sha256"]),
        ("uv.lock", manifest["lockfile_sha256"]),
    ):
        path = project_root / filename
        actual = sha256_file(path) if path.is_file() else "missing"
        lines.append(f"Current {filename} SHA-256: {actual} (matches: {actual == expected})")
    state = load_state(manifest)
    lines.append("State manifest: " + (json.dumps(state, sort_keys=True) if state else "missing"))
    reasons = stale_reasons(manifest, project_root)
    lines.append(f"Environment state: {'current' if not reasons else 'stale'}")
    for reason in reasons:
        lines.append(f"  stale reason: {reason}")
    for artifact in manifest["approved_artifacts"]:
        lines.append(
            f"Approved artifact: {artifact['distribution_name']}=={artifact['version']} "
            f"{artifact['filename']} SHA-256 {artifact['sha256']}"
        )
    for name in manifest["configuration_presence_names"]:
        lines.append(f"{name} present: {'yes' if bool(os.environ.get(name)) else 'no'}")
    if manifest.get("project_write_probe_required"):
        try:
            probe_project_write(project_root, manifest["application_display_name"])
            lines.append("Project write access: available")
        except Exception as exc:
            lines.append(f"Project write access: unavailable ({exc})")
    for requirement in manifest["external_runtimes"]:
        if "WebView2" in requirement["name"]:
            detected = detect_webview2()
            status = (
                f"installed, version {detected['version']}"
                if detected["installed"]
                else "not detected"
            )
            lines.append(f"Microsoft Edge WebView2 Runtime: {status}")
            lines.append(f"Feature affected: {requirement.get('feature') or 'core'}")
    if manifest["bootstrap_mode"] == "online_cmd":
        lines.extend(
            [
                f"curl.exe: {executable_observation('curl.exe', ['--version'])}",
                f"tar.exe: {executable_observation('tar.exe', ['--version'])}",
                f"certutil.exe: {executable_observation('certutil.exe', ['-?'])}",
            ]
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    for line in report(arguments.project_root.resolve()):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
