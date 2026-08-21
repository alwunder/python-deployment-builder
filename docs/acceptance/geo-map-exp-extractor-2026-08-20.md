# Geo Map Exp Extractor Windows acceptance — 2026-08-20

## Scope and traceability

This record covers the first real end-user acceptance of Python Deployment Builder's Windows
`uv_managed` backend. It establishes pilot readiness for applications within the currently
supported source-deployment shape; it does not claim universal Windows compatibility.

| Item | Accepted value |
| --- | --- |
| Python Deployment Builder | 0.1.0 at `d5400f6b8b08311e895c5f9e03c4e82b956df31c` |
| Geo Map Exp Extractor | `c2865e3ccea26d55f00ddfd3a01648d4382e286d` |
| Account type | Windows Standard User |
| Bootstrap | bundled uv 0.12.5 |
| Managed runtime | CPython 3.12.14 |
| Environment policy | locked, no source builds, no development extras |
| Elevation | not requested or required |
| PowerShell | not used or required |

The deployment provisioned application state under the user's LocalAppData and did not require a
preinstalled Python, Git, IDE, PATH change, or machine-wide installation.

## First acceptance round

The first round used a fresh Windows Standard User profile. The bundled, verified uv bootstrap
downloaded and provisioned managed CPython 3.12.14, then created the per-application environment
from the verified `uv.lock` using locked/no-build policy.

The following behavior passed:

- first-user runtime and environment provisioning without elevation or PowerShell;
- GUI launch and access to repository-adjacent profiles and resources;
- image/file browsing and project-local output behavior;
- startup without an OpenAI API key;
- session API-key entry through the application's existing UI;
- fast second launch using the fingerprinted deployment state;
- generated Diagnose and Repair workflows.

This round discovered an application-level portability defect: a copied or moved completed
project/run folder could retain references to its original location. The issue was reported as a
Geo application concern rather than hidden or worked around in the deployment builder.

## Application fix and second regression round

Geo Map Exp Extractor was updated so a loaded project/run folder is authoritative for its local
image, rows, notes/feedback, and related files. That fix and the reviewed `uv.lock` were committed
to Geo main at the source commit recorded above. A new deployment kit was then generated from that
commit.

The second round reused the same Standard User environment, so managed Python was already present;
it did **not** independently repeat fresh Python provisioning. The generated deployment correctly
detected the changed lock/deployment fingerprint and rebuilt the application environment. Testing
then confirmed:

- the updated GUI launched and retained the no-admin, no-PowerShell contract;
- a complete project/run folder could be copied or moved and reopened with **Load Project**;
- the copied folder remained authoritative both while the original existed and after the original
  was renamed or removed;
- image preview, extracted rows, notes/feedback, and other project-local files loaded from the
  copied location;
- a real image was successfully processed through the OpenAI API using session key entry;
- fast subsequent launch, Diagnose, and Repair continued to work;
- update/stale-environment detection rebuilt the environment when deployment inputs changed.

No API key value was included in deployment metadata, state, diagnostics, or acceptance reports.

## Result

The Windows `uv_managed` backend is **pilot ready** for the supported source-deployment shape. New
applications still require assessment, planning, locked-artifact review, developer-side validation,
and representative manual Standard User testing. First-run network access remains necessary for
managed Python and locked package downloads unless a future offline bundle or organizational cache
is provided.
