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
```

Persisted artifacts carry a schema version. Assessment models record facts, evidence, confidence,
and uncertainty. Planner models record choices. This prevents backend policy from contaminating
the repository evidence.

## Components

1. `analysis.repository` accepts a local path or safely materializes a public GitHub archive.
2. `analysis.metadata` reads standardized packaging and Python constraints without executing code.
3. `analysis.imports` classifies AST imports against the standard library, local modules, and
   declared distribution-to-import mappings.
4. `analysis.runtime_assumptions` identifies GUI, subprocess, external-runtime, environment,
   path, and write clues with source evidence.
5. `analysis.resources`, `analysis.dependencies`, and `analysis.risks` turn evidence into resource,
   compatibility, and GREEN/YELLOW/RED findings.
6. `planning` selects deployment mode and Python version from assessment facts plus policy, can
   explicitly inspect PyPI-published wheels, and applies a separate risk gate.
7. `backends.base` defines the runtime protocol; `uv_managed` produces the first concrete runtime
   plan, exact commands, environment variables, pinned artifact URL, and checksum.
8. `generation` will render a self-sufficient Windows kit with thin BAT entry points and a helper
   that runs only after bootstrap has provisioned managed Python.
9. `validation` will keep non-executing checks separate from explicitly opted-in installation and
   target execution.

## Windows uv-managed policy direction

The planner uses a pinned uv release and checksum-verified official binary, a controlled
LocalAppData tool/runtime/cache root, an external per-application environment, and frozen lockfile
semantics. Its end-user sync policy disables source builds and lock updates. It never modifies
PATH or registers managed Python. The generator must support an eventual bundled/offline uv
source without making Internet access intrinsic to the backend interface.

Normal launch compares schema, selected Python, pinned uv, project metadata, lockfile, generated
requirements, environment path, and prior verification fingerprints. Matching state takes a quick
launch-critical path. Changed state triggers a scoped sync or rebuild. Repair affects only the
current user's named application environment and retains rollback state until verification passes.

## Milestones

1. Foundation: models, safe repository loading, static analysis, reports, fixtures, tests, and a
   real assessment of `geo-map-exp-extractor`.
2. Planner: deployment policies, runtime protocol, uv-managed backend plan, Python selection,
   online wheel evidence, risk gating, and plan reports.
3. Generator: pinned/checksummed uv bootstrap, LocalAppData paths, frozen sync, source/package
   launch modes, metadata, fast path, repair, diagnosis, logging, redaction, and dry-run.
4. Validation: static consistency checks, isolated opt-in runtime setup/import checks, safe CLI
   help checks, manual GUI smoke-test instructions, and validation reports.

The first target remains urgent: general abstractions are added only when they directly support
the Windows + uv-managed deployment or a clear future backend boundary.
