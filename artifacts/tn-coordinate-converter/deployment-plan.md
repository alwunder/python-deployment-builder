# Deployment plan

**Gate: ALLOW WITH WARNINGS** — Planning may continue while generation remains subject to readiness gates.

- Schema version: `1.0`
- Generated: `2026-08-20T03:55:38.650564+00:00`
- Application: `Tn Coordinate Converter` (`tn-coordinate-converter`)
- Assessment fingerprint: `714a926321fba5a3fd6b2bc982a4ad610d15a0138203ad2ab241879bd29a9fe8`
- Deployment mode: `source`
- Entry point: `tn-coordinate-converter` → `tn_coord_converter_gui:main`
- Deployment readiness: `BLOCKED_PENDING_DEVELOPER_ARTIFACT`

## Decisions

### Deployment Mode: `source`

Repository-adjacent resources or project-local writes make an extracted-source layout the safest initial policy.

Alternatives: `package`, `source_resource_copy`

### Python Version: `3.12`

Selected from metadata plus requested wheel evidence.

Alternatives: `3.13`, `3.11`, `3.14`

### Runtime Backend: `uv_managed`

Use pinned uv and managed CPython, never an unknown system interpreter.

Alternatives: `existing_python`, `offline_bundle`, `custom_runtime`

### Entry Point: `tn-coordinate-converter`

Prefer a declared GUI entry point for the end-user launcher when available.

Alternatives: `tn-coordinate-converter-gui`

### Selected Extras: `map`

Only extras explicitly selected by the deployment developer are installed.

Alternatives: `dev`

## Python candidates

| Version | Selected | Metadata | Compatibility | Rationale |
|---|---|---|---|---|
| `3.12` | yes | satisfies | viable | Satisfies declared Python metadata. All selected direct dependencies publish compatible wheels. Selected by the policy preference order. |
| `3.13` | no | satisfies | viable | Satisfies declared Python metadata. All selected direct dependencies publish compatible wheels. |
| `3.11` | no | satisfies | viable | Satisfies declared Python metadata. All selected direct dependencies publish compatible wheels. |
| `3.14` | no | satisfies | viable | Satisfies declared Python metadata. All selected direct dependencies publish compatible wheels. |

## Managed runtime

- Backend: `uv_managed`
- Windows architecture: `x86_64`
- Python minor: `3.12`
- Pinned uv: `0.12.5`
- uv archive: `https://releases.astral.sh/github/uv/releases/download/0.12.5/uv-x86_64-pc-windows-msvc.zip`
- uv SHA-256: `4c4d49d8738847d9b71ba319e49a5688c93eac0fe6204b1df24e98528dddf39a`
- Shared root: `%LOCALAPPDATA%\PythonDeploymentBuilder`
- Application environment: `%LOCALAPPDATA%\PythonDeploymentBuilder\apps\tn-coordinate-converter\env`
- PATH and Windows registry integration: disabled
- Source builds during end-user sync: disabled

### Planned commands

- Provision: `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe python install 3.12 --install-dir %LOCALAPPDATA%\PythonDeploymentBuilder\python --no-bin --managed-python`
- Locked sync: `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe sync --locked --no-build --managed-python --python 3.12 --no-dev --extra map --no-install-project`

## Lockfile policy

- Status: `present_unverified`
- End-user policy: `locked`
- End-user updates allowed: `false`
- Developer preparation:
  - `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe lock --check` — Prove the committed lockfile is current before deployment generation.

## Optional features

| Extra | Recommended | Selected | Applicable dependencies | Policy |
|---|---|---|---|---|
| `map` | yes | yes | `clr-loader, pythonnet, pywebview` | Explicitly selected by the deployment developer. |
- Recommendation for `map`: Application source references pywebview, which is supplied by the optional 'map' feature.
| `dev` | no | no | `pytest, ruff` | Excluded by default; optional extras require explicit deployment selection. |

## PowerShell-free bootstrap policy

- Preferred mode: `bundled_uv`
- Command prompt required: `true`
- PowerShell allowed: `false`
- TLS verification required: `true`
- Security bypass allowed: `false`
- `bundled_uv` (supported): network=false; host tools: `none`. Use a developer-verified pinned uv.exe included in the generated kit.
- `online_cmd` (supported): network=true; host tools: `curl.exe, certutil.exe, tar.exe`. Use cmd.exe plus explicitly preflighted native Windows tools; no shell substitution is permitted.
  - `curl.exe`: Download the pinned official uv archive over HTTPS. Execution preflight required: `true`.
  - `certutil.exe`: Calculate SHA-256 for comparison with pinned deployment metadata. Execution preflight required: `true`.
  - `tar.exe`: Extract the checksum-verified uv ZIP archive. Execution preflight required: `true`.
- `offline_bundle` (future): network=false; host tools: `none`. Future bundle containing uv, managed Python, and approved artifacts.
- Unavailable policy: If HTTPS or a required native executable is missing or policy-blocked, online_cmd is unavailable; require bundled_uv or a future offline bundle without bypassing policy.

## Locked dependency artifacts

| Package | Version | Direct | Feature | Chain | Artifact policy |
|---|---|---|---|---|---|
| `clr-loader` | `0.3.1` | yes | `map` | `tn-coordinate-converter → clr-loader` | `wheel_usable` |
| `pyproj` | `3.7.2` | yes | `core` | `tn-coordinate-converter → pyproj` | `wheel_usable` |
| `pythonnet` | `3.1.0` | yes | `map` | `tn-coordinate-converter → pythonnet` | `wheel_usable` |
| `pywebview` | `6.2.1` | yes | `map` | `tn-coordinate-converter → pywebview` | `wheel_usable` |
| `bottle` | `0.13.4` | no | `map` | `tn-coordinate-converter → pywebview → bottle` | `wheel_usable` |
| `certifi` | `2026.7.22` | no | `core` | `tn-coordinate-converter → pyproj → certifi` | `wheel_usable` |
| `cffi` | `2.1.1` | no | `map` | `tn-coordinate-converter → clr-loader → cffi` | `wheel_usable` |
| `proxy-tools` | `0.1.0` | no | `map` | `tn-coordinate-converter → pywebview → proxy-tools` | `developer_wheel_required` |
| `pycparser` | `3.0` | no | `map` | `tn-coordinate-converter → clr-loader → cffi → pycparser` | `wheel_usable` |
| `typing-extensions` | `4.16.0` | no | `map` | `tn-coordinate-converter → pywebview → typing-extensions` | `wheel_usable` |

### Developer artifact required: `proxy-tools==0.1.0`

No compatible locked wheel is available. End-user source builds remain disabled; developer preparation must supply an approved wheel.

Dependency chain: `tn-coordinate-converter → pywebview → proxy-tools`
Selected feature: `map`

## External runtimes

- **needs_validation: Microsoft Edge WebView2 Runtime** — platform `windows`; launch required: `false`; feature `map` required: `true`. Preflight the pywebview EdgeChromium backend and report WebView2 availability; do not launch the long-running GUI during unattended validation. Automatic installation: `never_automatic`.

## Windows platform applicability

| Finding | Platforms | Treatment | Rationale |
|---|---|---|---|
| `external_executable: dynamic subprocess command` | `unknown` | `needs_validation` | Platform applicability is not statically certain. |
| `gui_toolkit: pywebview` | `all` | `applicable` | The finding can apply to the Windows deployment target. |
| `gui_toolkit: Tkinter` | `all` | `applicable` | The finding can apply to the Windows deployment target. |
| `path_assumption: repository-root derived from __file__` | `all` | `applicable` | The finding can apply to the Windows deployment target. |
| `subprocess: subprocess` | `all` | `applicable` | The finding can apply to the Windows deployment target. |

## Risk treatment

- Warnings: `NATIVE_WHEELS_UNVERIFIED`, `REPOSITORY_ADJACENT_RESOURCES`
- Blocking findings: none
- Readiness blockers: `DEVELOPER_ARTIFACT_REQUIRED:proxy-tools==0.1.0`
- Readiness pending: `LOCKFILE_CURRENTNESS_UNVERIFIED`

## Configuration and writes

- No configuration requirements were detected.
- Project write probe required: `false`. No project-root write probe is required by static evidence.

## Online wheel inspection

- Assessed: `2026-08-20T03:55:37.968605+00:00`
- Source: `PyPI JSON API` (`https://pypi.org/pypi`)
- Targets: `3.12, 3.13, 3.11, 3.14` / `x86_64`

| Distribution | Release | Python | Wheel |
|---|---|---|---|
| `clr-loader` | `0.3.1` | `3.12` | available |
| `clr-loader` | `0.3.1` | `3.13` | available |
| `clr-loader` | `0.3.1` | `3.11` | available |
| `clr-loader` | `0.3.1` | `3.14` | available |
| `pythonnet` | `3.1.0` | `3.12` | available |
| `pythonnet` | `3.1.0` | `3.13` | available |
| `pythonnet` | `3.1.0` | `3.11` | available |
| `pythonnet` | `3.1.0` | `3.14` | available |
| `pywebview` | `6.2.1` | `3.12` | available |
| `pywebview` | `6.2.1` | `3.13` | available |
| `pywebview` | `6.2.1` | `3.11` | available |
| `pywebview` | `6.2.1` | `3.14` | available |
| `pyproj` | `3.7.2` | `3.12` | available |
| `pyproj` | `3.7.2` | `3.13` | available |
| `pyproj` | `3.7.2` | `3.11` | available |
| `pyproj` | `3.7.2` | `3.14` | available |

## Required validation

- Run uv lock --check before generation; do not rewrite the lockfile on the end-user PC.
- Verify imports in an isolated Windows environment without paid or destructive calls.
- Perform the GUI smoke test manually.
- Detect Microsoft Edge WebView2 Runtime for selected feature 'map'.

## Planning boundaries

- Lockfile currentness is not assumed from existence; developer preparation must run uv lock --check.
- No source distribution is built during assessment or planning.
- Bootstrap implementation, fast-path, repair, and diagnostics remain Milestone 3.
- Runtime installation and target execution require explicit Milestone 4 validation.
