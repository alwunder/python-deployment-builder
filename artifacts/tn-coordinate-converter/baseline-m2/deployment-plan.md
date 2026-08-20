# Deployment plan

**Gate: ALLOW WITH WARNINGS** — The deployment may proceed if generated checks preserve the listed safeguards.

- Schema version: `1.0`
- Generated: `2026-08-20T03:36:35.998680+00:00`
- Application: `Tn Coordinate Converter` (`tn-coordinate-converter`)
- Assessment fingerprint: `714a926321fba5a3fd6b2bc982a4ad610d15a0138203ad2ab241879bd29a9fe8`
- Deployment mode: `source`
- Entry point: `tn-coordinate-converter` → `tn_coord_converter_gui:main`

## Decisions

### Deployment Mode: `source`

Repository-adjacent resources or project-local writes make an extracted-source layout the safest initial policy.

Alternatives: `package`, `source_resource_copy`

### Python Version: `3.12`

Selected independently from assessment facts using the managed-runtime policy and wheel evidence when requested.

Alternatives: `3.13`, `3.11`, `3.14`

### Runtime Backend: `uv_managed`

Use pinned uv and managed CPython rather than an unknown system interpreter.

Alternatives: `existing_python`, `offline_bundle`, `custom_runtime`

### Entry Point: `tn-coordinate-converter`

Prefer a declared GUI entry point for the end-user launcher when available.

Alternatives: `tn-coordinate-converter-gui`

## Python candidates

| Version | Selected | Metadata | Compatibility | Rationale |
|---|---|---|---|---|
| `3.12` | yes | satisfies | viable | Satisfies declared Python metadata. All inspected direct runtime dependencies publish compatible wheels. Selected by the policy preference order. |
| `3.13` | no | satisfies | viable | Satisfies declared Python metadata. All inspected direct runtime dependencies publish compatible wheels. |
| `3.11` | no | satisfies | viable | Satisfies declared Python metadata. All inspected direct runtime dependencies publish compatible wheels. |
| `3.14` | no | satisfies | viable | Satisfies declared Python metadata. All inspected direct runtime dependencies publish compatible wheels. |

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
- Frozen sync: `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe sync --frozen --no-dev --no-build --managed-python --python 3.12 --no-install-project`

## Lockfile policy

- Status: `present`
- End-user policy: `frozen`
- End-user updates allowed: `false`

## Risk treatment

- Warnings: `UNDECLARED_IMPORTS`, `NATIVE_WHEELS_UNVERIFIED`, `REPOSITORY_ADJACENT_RESOURCES`
- Blocking findings: none

## Configuration and writes

- No configuration requirements were detected.
- Project write probe required: `false`. No project-root write probe is required by static evidence.

## Online wheel inspection

- Assessed: `2026-08-20T03:36:35.612741+00:00`
- Source: `PyPI JSON API` (`https://pypi.org/pypi`)
- Targets: `3.12, 3.13, 3.11, 3.14` / `x86_64`

| Distribution | Release | Python | Wheel |
|---|---|---|---|
| `pyproj` | `3.7.2` | `3.12` | available |
| `pyproj` | `3.7.2` | `3.13` | available |
| `pyproj` | `3.7.2` | `3.11` | available |
| `pyproj` | `3.7.2` | `3.14` | available |

## Required validation

- Verify the committed uv.lock is current before generation.
- Verify imports in the isolated Windows environment without making paid API calls.
- Perform the GUI smoke test manually.

## Planning boundaries

- The plan does not mutate the repository or generate the missing uv.lock.
- End-user bootstrap, fast-path, repair, diagnostics, and template rendering are Milestone 3.
- Runtime installation and target execution require explicit Milestone 4 validation.
- Online inspection covers declared direct dependencies; lock/runtime validation must verify transitive dependencies such as native extension helpers.
