# Pinned uv 0.12.5 developer acceptance

Acceptance was run on Windows x86_64 on 2026-08-20 with the exact official
`uv-x86_64-pc-windows-msvc.zip` selected by the deployment plan. The archive matched the pinned
SHA-256, and the extracted executable reported:

```text
uv 0.12.5 (210d1f678 2026-08-14 x86_64-pc-windows-msvc)
```

The repeatable script is `scripts/verify_uv_0125.py`. It uses an isolated temporary project,
cache, managed-Python root, and application environment. It does not execute either reference
application.

Verified behavior:

- `uv python install 3.12 --install-dir ... --no-bin --no-registry --managed-python` installed
  managed CPython 3.12.14 without creating PATH or registry integration.
- `UV_PROJECT_ENVIRONMENT` created the environment at the controlled external location and did not
  create a project `.venv`.
- `uv lock --python 3.12` and `uv lock --check --python 3.12` succeeded.
- `uv sync --locked --no-build --managed-python --python 3.12 --no-dev --extra map
  --no-install-project` is supported by 0.12.5.
- `UV_SYSTEM_CERTS=true` is accepted and consistently applied.
- Managed CPython 3.12 executed `manage.py`, `launch.py`, and `diagnostics.py` with the production
  `-B -E -s` flags; every helper imported its generated sibling modules even with a hostile
  `PYTHONPATH` value present in the parent environment.
- A source-only locked exception can be omitted with `--no-install-package proxy-tools`, followed
  by installation of an exact local pure-Python wheel through `uv pip install --python ...
  --no-deps --no-build` and `uv pip check`.

An exact subsequent sync removes that locally installed exception because it is deliberately
omitted from the sync set. This is expected and is incorporated into the generated transactional
setup: every rebuild performs the locked/no-build sync, immediately reinstalls every hash-verified
approved wheel, checks dependency consistency, verifies the entry-point module, and only then
writes successful state. The normal fast path performs no sync, so it cannot remove the artifact.

This test proves the pinned package-manager command contract. It does not approve a particular
third-party wheel or prove either application's GUI on a fresh workstation; those are separate
developer approval and Milestone 4 validation responsibilities.
