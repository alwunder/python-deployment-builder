# Deployment plan

**Gate: ALLOW WITH WARNINGS** — The deployment may proceed if generated checks preserve the listed safeguards.

- Schema version: `1.0`
- Generated: `2026-08-19T19:28:48.945425+00:00`
- Application: `Geo Map Exp Extractor` (`geo-map-exp-extractor`)
- Assessment fingerprint: `f9112964e1238f7e9080130cd74b7cdf11e81c0bd2a1d84ae6d15f22f054d8a8`
- Deployment mode: `source`
- Entry point: `geo-image-extract-gui` → `geo_map_exp_extractor.gui:main`

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

### Entry Point: `geo-image-extract-gui`

Prefer a declared GUI entry point for the end-user launcher when available.

Alternatives: `geo-map-exp-extractor`

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
- Application environment: `%LOCALAPPDATA%\PythonDeploymentBuilder\apps\geo-map-exp-extractor\env`
- PATH and Windows registry integration: disabled
- Source builds during end-user sync: disabled

### Planned commands

- Provision: `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe python install 3.12 --install-dir %LOCALAPPDATA%\PythonDeploymentBuilder\python --no-bin --managed-python`
- Frozen sync: `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe sync --frozen --no-dev --no-build --managed-python --python 3.12 --no-install-project`

## Lockfile policy

- Status: `developer_generation_required`
- End-user policy: `frozen`
- End-user updates allowed: `false`
- Developer preparation:
  - `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe lock --python 3.12` — Generate the application lockfile during developer-side preparation.
  - `%LOCALAPPDATA%\PythonDeploymentBuilder\tools\uv\0.12.5\uv.exe lock --check` — Verify the committed lockfile matches project metadata.

## Risk treatment

- Warnings: `DEPENDENCY_LOCK_MISSING`, `NATIVE_WHEELS_UNVERIFIED`, `REPOSITORY_ADJACENT_RESOURCES`, `PROJECT_LOCAL_WRITES`, `SECRET_CONFIGURATION`
- Blocking findings: none

## Configuration and writes

- `OPENAI_API_KEY` — `existing_application_workflow`; value persisted: `false`; value logged: `false`. Keep the GUI's existing optional/session configuration workflow; record presence only and validate that launch does not require the secret.
- `.env.example` — `manual_review`; value persisted: `false`; value logged: `false`. Supply configuration outside deployment metadata and never record secret values.
- Project write probe required: `true`. Fail clearly without elevation and direct the user to a writable extraction/output location.

## Online wheel inspection

- Assessed: `2026-08-19T19:28:47.401625+00:00`
- Source: `PyPI JSON API` (`https://pypi.org/pypi`)
- Targets: `3.12, 3.13, 3.11, 3.14` / `x86_64`

| Distribution | Release | Python | Wheel |
|---|---|---|---|
| `openai` | `3.3.1` | `3.12` | available |
| `openai` | `3.3.1` | `3.13` | available |
| `openai` | `3.3.1` | `3.11` | available |
| `openai` | `3.3.1` | `3.14` | available |
| `Pillow` | `12.3.0` | `3.12` | available |
| `Pillow` | `12.3.0` | `3.13` | available |
| `Pillow` | `12.3.0` | `3.11` | available |
| `Pillow` | `12.3.0` | `3.14` | available |
| `pydantic` | `2.13.4` | `3.12` | available |
| `pydantic` | `2.13.4` | `3.13` | available |
| `pydantic` | `2.13.4` | `3.11` | available |
| `pydantic` | `2.13.4` | `3.14` | available |
| `PyYAML` | `6.0.3` | `3.12` | available |
| `PyYAML` | `6.0.3` | `3.13` | available |
| `PyYAML` | `6.0.3` | `3.11` | available |
| `PyYAML` | `6.0.3` | `3.14` | available |
| `rich` | `15.0.0` | `3.12` | available |
| `rich` | `15.0.0` | `3.13` | available |
| `rich` | `15.0.0` | `3.11` | available |
| `rich` | `15.0.0` | `3.14` | available |
| `tksheet` | `7.6.0` | `3.12` | available |
| `tksheet` | `7.6.0` | `3.13` | available |
| `tksheet` | `7.6.0` | `3.11` | available |
| `tksheet` | `7.6.0` | `3.14` | available |
| `typer` | `0.27.1` | `3.12` | available |
| `typer` | `0.27.1` | `3.13` | available |
| `typer` | `0.27.1` | `3.11` | available |
| `typer` | `0.27.1` | `3.14` | available |

## Required validation

- Verify the committed uv.lock is current before generation.
- Verify imports in the isolated Windows environment without making paid API calls.
- Perform the GUI smoke test manually.
- Confirm the GUI launches without secret configuration and retains its session-entry workflow.
- Probe project/output write access before launch.

## Planning boundaries

- The plan does not mutate the repository or generate the missing uv.lock.
- End-user bootstrap, fast-path, repair, diagnostics, and template rendering are Milestone 3.
- Runtime installation and target execution require explicit Milestone 4 validation.
- Online inspection covers declared direct dependencies; lock/runtime validation must verify transitive dependencies such as native extension helpers.
