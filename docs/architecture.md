# Architecture and implementation plan

## Boundary

Python Deployment Builder runs only on the developer machine. Generated deployment kits contain
rendered bootstrap/runtime helpers and metadata; they never import or require the builder package
on the end-user machine.

```text
repository -> static assessment -> deployment policy -> backend plan
                                                     -> generated kit
                                                     -> static validation
                                                     -> opt-in runtime validation
                                                     -> deterministic package
                                                     -> human acceptance
                                                     -> external publication
```

Persisted artifacts carry a schema version. Assessment models record facts, evidence, confidence,
and uncertainty. Planner models record choices. This prevents backend policy from contaminating
the repository evidence.

## Components

1. `analysis.repository` accepts a local path or safely materializes a public GitHub archive.
2. `analysis.inventory` assigns repository roles from source-layout, conventional-scope, and
   root/nested gitwildmatch-ignore evidence, providing the application-file set shared by runtime
   scanners without requiring Git. Strong import/resource evidence can promote conventional
   non-runtime roles, while ignored runtime dependencies remain excluded and blocking.
3. `analysis.metadata` reads standardized packaging, legacy dependency groups, and Python
   constraints without executing code.
4. `analysis.imports` classifies scoped AST imports and records module-top-level, deferred,
   conditional, and `TYPE_CHECKING` contexts.
5. `analysis.entrypoints` finds diagnostic `__main__` candidates without authorizing or executing
   them; standardized metadata remains authoritative.
6. `analysis.runtime_assumptions` identifies GUI, subprocess, external-runtime, environment,
   path, and write clues with source evidence.
7. `analysis.resources`, `analysis.dependencies`, `analysis.guidance`, and `analysis.risks` turn
   scoped evidence into resources, compatibility, structural teaching, and GREEN/YELLOW/RED
   findings. Existing deployment machinery and vendor-runtime evidence remain separate.
8. `planning` selects deployment mode, Python version, and explicit optional features from
   assessment facts plus policy; it can inspect PyPI-published wheels, traverse the applicable
   locked graph, model external runtimes and platform applicability, and apply separate assessment
   and deployment-readiness gates.
9. `backends.base` defines the runtime protocol; `uv_managed` produces the first concrete runtime
   plan, exact commands, environment variables, pinned artifact URL, and checksum.
10. `generation` renders a staged Windows kit with thin BAT entry points, an initial CMD bootstrap,
   and independent standard-library Python helpers used only after managed Python exists.
11. `validation` keeps non-executing staged-kit integrity checks separate from explicitly opted-in
   installation and controlled target imports. Runtime validation uses an isolated LocalAppData
   root and exercises first setup, fast state, staleness, rollback, repair, and diagnostics without
   launching a GUI.
12. `packaging` accepts only a statically valid deployment kit, creates a deterministic ZIP and
    checksum, safely extracts and revalidates it, then emits schema-versioned release provenance
     and a human smoke-test handoff. It does not publish or claim application acceptance.

The assessment repository fingerprint is explicitly a `deployment_inputs` identity. Its inputs are
scoped application Python, detected immutable runtime resources, standardized/legacy dependency
metadata, lockfiles, and ignore policy. It deliberately excludes ordinary tests, documentation,
examples, deployment support, and ignored/local files unless stronger runtime evidence promotes a
path. It is neither a whole-repository identity nor the generated kit integrity mechanism. Optional
Git revision records source provenance, while generated-file hashes cover every staged file.
Generation consumes the role-aware inventory: source mode normally stages only application source,
runtime resources, and required backend metadata. Package mode stages backend metadata, generated
runtime material, approved dependency artifacts, and a validated first-party application wheel.
Deployment support and unknown/local material are not silently promoted into either mode.

Planning retains all safely detected blocker codes. Its single readiness state is a primary summary
selected in this order: blocking assessment risk, missing authoritative entry point, selected
developer artifact, missing lockfile, then lock verification. Online compatibility for nonselected
legacy requirement groups remains informational and cannot create a selected-artifact blocker.
Assessment/plan schema 1.1 reports are current outputs rather than reloadable workflow inputs;
commands recompute them from repositories. Deployment and release manifests use their own schemas.
Pre-M6.1 source-mode manifests remain validation- and packaging-compatible through optional defaults
for new fields. Package mode begins with M6.1 and requires a validated first-party application
artifact; a package-mode manifest without one is an explicit contract failure, not an implicit
backward-compatible source deployment.

## Windows uv-managed policy direction

The planner uses a pinned uv release and checksum-verified official binary, a controlled
LocalAppData tool/runtime/cache root, an external per-application environment, and `--locked`
lockfile semantics. Its end-user sync policy detects stale project metadata, disables source
builds, and never updates the lockfile. Developer preparation always runs `uv lock --check`; it
first runs `uv lock --python <minor>` when the project has no lockfile. It never modifies PATH or
registers managed Python.

PowerShell is not an end-user deployment capability or fallback. The preferred bootstrap mode is
`bundled_uv`, where the developer prepares and verifies the pinned binary. `online_cmd` uses
`cmd.exe` and explicitly preflights `curl.exe`, `certutil.exe`, and `tar.exe`. Missing or
policy-blocked tools make that mode unavailable without any security bypass. A future
`offline_bundle` can also supply managed Python and approved artifacts.

Selected extras are explicit, repeatable inputs. They propagate into compatibility evidence,
locked-graph traversal, runtime sync commands, external-runtime rules, and stale-state
fingerprints. Development extras are excluded by default. Source-only locked packages produce a
developer-artifact requirement; assessment and planning never execute their build hooks, and an
end-user environment never performs an unexpected source build.

Source mode is permitted only when the authoritative standardized entry-point module is
structurally importable from the planned source roots without installing the project. If metadata
uses an installed namespace that differs from its physical source namespace, PDB selects package
mode when package metadata/resources are install-safe; genuine source-only constraints instead
produce a typed deployment-mode conflict. Package mode requires a developer-supplied first-party
wheel. Its name, version, tags, entry point, module, package data, pure-Python contents, and hash are
validated, and its provenance is recorded separately from exceptional dependency artifacts and
from the assessed source revision. The exact supplied wheel bytes are authoritative; ordinary
wheel metadata alone is not evidence that those bytes were built from the recorded revision.

Normal launch compares schema, selected Python, pinned uv, project metadata, lockfile, selected
extras, approved artifact hashes, environment path, and prior verification fingerprints. Matching
state takes a quick launch-critical path. Changed state triggers a scoped rebuild at the final
environment path after moving the current environment to `env.previous`; failure restores it.
Repair affects only `env`, `env.previous`, `env.failed`, and state directly beneath the current
user's expected application root.

Developer generation and end-user setup are separate trust boundaries. The developer may
explicitly create a missing lock, acquire/verify uv, and approve a compatible local wheel. The
end-user bootstrap never resolves an updated lock or builds an sdist. Generated helpers verify
project, lock, bundled-tool, and artifact fingerprints before setup and state promotion.

Developer repository preparation is also distinct from distribution generation. An explicitly
created and checked `uv.lock` can be reviewed and optionally committed on a deployment-preparation
branch, while the staged source copy, bundled runtime, launchers, manifests, wheels, logs, and ZIP
remain generated distribution material. A future `prepare` command and committed deployment policy
file makes recurring architecture/bootstrap/certificate/extra defaults explicit without folding
policy back into assessment. Configuration is strict and optional; CLI inputs remain authoritative.

Generated Python helpers run with `-B -E -s`, not `-I`: Python avoids bytecode writes, ignores
user-controlled `PYTHON*` interpreter configuration, and excludes user site-packages while
retaining the script directory so the standalone helpers can import their generated siblings.
In source mode, `launch.py` inserts only the manifest's source roots immediately before controlled
entry-point import; it does not rely on `PYTHONPATH`. In package mode it adds no application source
root and imports the authoritative target from the managed environment after the exact first-party
wheel has been installed.

For a Git source with a recorded revision, generation intersects role-approved staging with
tracked paths and blocks when any selected tracked deployment input differs from `HEAD`. It does
not elevate ignored, untracked, documentation, example, test, deployment-support, or mutable-state
roles merely because a filename looks executable or resource-like. Non-Git directories and safely
materialized archives use the same role inventory without requiring Git; eligible application
source and runtime resources are staged directly in source mode, while package mode stages all
application runtime content only from its validated first-party wheel.

The online bootstrap's localized `certutil.exe` handling searches structurally for one 64-digit
hexadecimal value rather than parsing English headings. Missing, blocked, download-failing, and
checksum-failing stages remain distinct log causes. Corporate trust uses `UV_SYSTEM_CERTS=true`;
TLS validation and organizational controls are never bypassed.

## Milestones

1. Foundation: models, safe repository loading, static analysis, reports, fixtures, tests, and a
   real assessment of `geo-map-exp-extractor`.
2. Planner: deployment policies, runtime protocol, uv-managed backend plan, Python selection,
   online wheel evidence, risk gating, and plan reports.
2.5. Cross-project planner hardening: selected extras, applicable markers, locked transitive
   artifacts, external runtimes, platform treatment, typed readiness, source paths for `src/` and
   flat layouts, and a PowerShell-free bootstrap contract.
3. Generator: pinned/checksummed uv acquisition and CMD bootstrap, LocalAppData paths, locked
   no-build sync, source launch modes, manifests, collision safety, fast path, rollback repair,
   diagnosis, WebView2 detection, logging, redaction, structural checks, and dry-run.
4. Validation: static consistency checks, isolated opt-in runtime setup/import checks, actual
   generated-helper subprocess checks, fast/stale/rollback/repair/diagnostic evidence, manual GUI
   smoke-test instructions, and schema-versioned validation reports.
5. Release packaging and workflow productization: strict optional repository defaults,
   deterministic content-root ZIPs, SHA-256 checksum and release provenance, safe extracted-ZIP
   revalidation, generic evidence-driven smoke-test handoff, and `all` orchestration with an
   explicit runtime-validation trust boundary. Publication remains external.
6. Analysis scope, structural guidance, and incomplete planning: role/ignore-aware runtime scans,
   resource and mutable-state evidence, diagnostic entry-point candidates, import contexts,
   existing deployment/vendor-runtime inventory, typed teaching guidance, and plans that report
   all safe blockers before refusing generation.
6.1. Generation contract: source-entry-point compatibility gating, explicit validated first-party
   wheels for package mode, installed-target launch, application-artifact provenance, and
   role-aware tracked-file staging with generic runtime-cache exclusion.

The first target remains urgent: general abstractions are added only when they directly support
the Windows + uv-managed deployment or a clear future backend boundary.
