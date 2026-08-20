# Python Deployment Builder

Python Deployment Builder is a developer-side tool for turning a Python repository into a
repeatable, non-admin Windows deployment. It separates repository analysis from deployment
policy and keeps the generated end-user kit independent of the builder itself.

```text
Python Deployment Builder (developer machine)
        assess -> plan -> generate -> validate
                              |
                              v
                  generated deployment kit
                              |
                              v
                 Windows standard-user machine
```

The first backend is Windows with pinned `uv`, uv-managed CPython, and one isolated environment
per application and Windows user. The design leaves room for other runtime backends, but the MVP
does not implement ArcGIS Pro, existing-Python, offline-bundle, or custom-runtime deployment.

## Current milestone

Milestones 1, 2, 2.5, and 3 are implemented: static assessment, explicit deployment planning, and
generation of a staged, PowerShell-free Windows deployment kit. Runtime validation and fresh-user
GUI proof remain Milestone 4 rather than being implied by successful generation.

```console
python -m pip install -e ".[dev]"
pdbuilder assess C:\path\to\repository
pdbuilder assess https://github.com/owner/public-repository
pdbuilder plan C:\path\to\repository
pdbuilder plan https://github.com/owner/public-repository --online
pdbuilder plan C:\path\to\repository --online --extra map
pdbuilder generate C:\path\to\repository --dry-run
pdbuilder generate C:\path\to\repository --prepare-lock --bootstrap bundled_uv
pdbuilder generate C:\path\to\repository --bootstrap bundled_uv --system-certs
```

By default, assessment reports are written beneath
`./pdbuilder-output/<application-id>/`. Choose a specific location with `--output-dir`:

```console
pdbuilder assess ..\geo-map-exp-extractor --output-dir artifacts\geo-map-exp-extractor
```

The result is:

```text
assessment.json   stable, typed automation input
assessment.md     developer-readable evidence and recommendations
deployment-plan.json   stable deployment policy and backend inputs
deployment-plan.md     human-readable decisions, risks, and commands
```

## Lifecycle and architecture

The implementation is divided into focused layers:

- `analysis`: safe repository materialization, packaging metadata, AST imports, resources,
  configuration, runtime assumptions, writes, dependencies, and risk rating;
- `planning`: policy decisions made from assessment facts, including Python/runtime selection,
  selected optional features, explicit PyPI wheel inspection, locked transitive artifact policy,
  external runtimes, platform treatment, readiness gating, and source-versus-package deployment;
- `backends`: runtime protocol plus the first `uv_managed` implementation;
- `generation`: verified pinned-uv acquisition, explicit lock preparation, approved-wheel checks,
  collision-safe staging, manifests, CMD bootstrap, standalone runtime helpers, fast launch,
  scoped repair, diagnostics, logging, redaction, and structural validation;
- `validation`: static checks by default and explicitly opted-in runtime execution (Milestone 4);
- `reporting`: schema-versioned JSON and companion Markdown at every stage.

Assessment describes evidence; planning chooses policy. For example, an assessment may establish
that Python 3.12 and 3.13 satisfy repository and dependency evidence, while a policy selects 3.12
for a particular release. This boundary allows future policies to reuse the same assessment.

See [docs/architecture.md](docs/architecture.md) for component boundaries and the implementation
sequence.

## Static-analysis safety and threat model

Unknown repositories are treated as untrusted code. Static assessment:

- does not import target modules;
- does not execute `setup.py`, project hooks, or entry points;
- does not install target dependencies;
- uses `tomllib`, configuration/text parsing, and Python AST parsing;
- reads `.env.example` as a configuration clue but does not read `.env` contents;
- accepts a local directory or downloads a public GitHub ZIP without requiring Git;
- rejects archive traversal, absolute paths, symbolic links, encrypted members, and configured
  archive/member/expanded-size limits.

Runtime validation will be a separate, explicit operation because installing or invoking a target
crosses this trust boundary.

## No-admin deployment philosophy

Planned/generated deployments use paths under `%LOCALAPPDATA%\PythonDeploymentBuilder`, exact
executable paths, and no machine or user PATH edits. They will not request elevation, modify system
Python, write to Program Files, weaken TLS/security controls, or attempt to bypass organizational
policy. A policy block will be reported plainly.

PowerShell is prohibited throughout the end-user deployment contract. Bootstrap, normal launch,
repair, diagnosis, logging, and cleanup must not emit `.ps1` files or invoke `powershell.exe` or
`pwsh.exe`. The preferred bootstrap is a developer-verified bundled `uv.exe`. An online bootstrap
may use only `cmd.exe` plus explicitly preflighted `curl.exe`, `certutil.exe`, and `tar.exe`; if
one is missing or policy-blocked, the plan requires the bundled or future offline route.

The intended runtime layout is:

```text
%LOCALAPPDATA%\PythonDeploymentBuilder\
    tools\uv\
    python\
    cache\
    apps\<application-id>\
        env\
        logs\
        state\
```

The pinned uv executable, compatible managed Python installations, and download cache can be
shared; environments, logs, metadata, repair, and deletion scope remain application-specific.

## Generating a deployment kit

Generation uses the `DeploymentPlan` as its source of truth. The default output is a separate
staging directory containing a sanitized copy of the source application plus the deployment
layer. Git/IDE state, `.env` files, tests, prior output/cache data, and credential files are not
copied. Pointing `--output-dir` at the repository root is explicit in-place generation; unknown or
locally modified file collisions are refused.

```text
Run <Application>.bat
Repair <Application> Environment.bat
Diagnose <Application>.bat
deployment\
    manifest.json
    generated-files.json
    bootstrap\
        bootstrap.cmd
        uv.exe                 (bundled_uv only)
    runtime\
        runtime_common.py
        manage.py
        launch.py
        diagnostics.py
    wheels\                    (approved artifacts only)
    README-deployment.txt
```

The root BAT files only delegate to `bootstrap.cmd`. Before Python exists, the bootstrap uses CMD
and, for `online_cmd`, preflighted `curl.exe`, `certutil.exe`, and `tar.exe`. After managed Python
exists, standard-library-only generated helpers own environment setup, fingerprinting, repair,
diagnostics, guarded deletion, logging, and launch. They do not import Python Deployment Builder.

`bundled_uv` is preferred: the developer downloads the exact planned uv ZIP, verifies its pinned
SHA-256, safely extracts it, checks `uv --version`, caches it, and places the verified executable in
the kit. `online_cmd` performs the same download/archive verification on the user machine without
using PowerShell. Neither mode modifies PATH or runs uv self-update.

`--system-certs` records and applies `UV_SYSTEM_CERTS=true` to uv operations. This uses the native
Windows certificate store for corporate trust roots without disabling TLS validation, changing
certificate stores, or adding insecure hosts.

### Developer preparation

Every real generation runs pinned `uv lock --check`. A stale lock stops generation without
rewriting it. A missing lock also stops unless `--prepare-lock` explicitly authorizes a local
repository mutation; URL inputs cannot use that option. The builder then runs
`uv lock --python <minor>`, checks the result, reports the changed `uv.lock`, and never commits it.

Typed `developer_wheel_required` findings can be satisfied with a validated exact wheel:

```console
pdbuilder generate C:\path\to\repository --extra map ^
  --artifact proxy-tools=C:\approved-wheels\proxy_tools-0.1.0-py3-none-any.whl
```

The wheel filename, distribution/version metadata, tags, RECORD structure, and SHA-256 are checked
without executing its code. uv 0.12.5 exact sync omits the named exception with
`--no-install-package`; the helper immediately installs the verified local wheel with `--no-deps`
and `--no-build`, runs `uv pip check`, then records successful state. Arbitrary sdist builds remain
disabled. See [docs/uv-0.12.5-acceptance.md](docs/uv-0.12.5-acceptance.md).

### Fast path, repair, and diagnosis

Normal launch compares schema, uv/Python versions, lock and project hashes, selected extras,
approved artifact hashes, and the expected environment path. A matching successful state launches
immediately; no routine uv sync or heavyweight import validation occurs. A stale setup is rebuilt
at the final environment path while the prior environment is retained for rollback on failure.

Repair rebuilds only this user's named application environment and state. Deletion guards restrict
operations to `env`, `env.previous`, and `env.failed` directly below the expected application root.
Diagnostics work at BAT level when Python is broken and become richer when the managed interpreter
is available. They report WebView2 through Microsoft's documented `pv` registry locations and
configuration presence only, never secret values.

## Reference applications

`geo-map-exp-extractor` is the first acceptance application. Its static assessment is
stored in [artifacts/geo-map-exp-extractor](artifacts/geo-map-exp-extractor) and rates it YELLOW:
likely deployable, with issues requiring deliberate planning.

The repository has standard metadata, a `src/` layout, Python `>=3.11`, CLI and GUI entry points,
Tkinter, and matched declared imports. It also deliberately relies on repository-adjacent
`profiles/`, `prompts/`, `README.md`, and `examples/`; derives the repository root from `__file__`;
and writes its default outputs/cache beneath the repository. Generation therefore requires an
explicit developer-prepared lock and emits a project write probe.

Those facts favor an initial source-based deployment with the environment stored elsewhere under
LocalAppData. That is a planner decision, not a special case embedded in the analyzer. The
application's session `Set API key...` workflow can remain unchanged, and deployment/validation
must not require or expose an API key.

`tn-coordinate-converter` is the cross-project planner test. Its current reports are stored in
[artifacts/tn-coordinate-converter](artifacts/tn-coordinate-converter). It uses flat modules, an
existing `uv.lock`, core `pyproj`, and an explicitly selected `map` extra while the `dev` extra is
excluded. The map feature adds `pywebview`, `pythonnet`, and `clr-loader`, requires WebView2 at
feature use rather than core launch, and exposes a locked transitive source-only dependency:
`pywebview -> proxy-tools`. End-user source builds remain prohibited, so readiness is blocked until
a developer supplies an approved compatible wheel. Lockfile existence is recorded as unverified
until developer preparation runs `uv lock --check`.

## SimpleGeorefGUI lessons

SimpleGeorefGUI and its deployment-hardening PR #63 inform generic behavior: per-user state, exact
runtime invocation, metadata/fingerprint stale detection, fast routine checks, deeper diagnosis,
scoped repair with rollback and deletion guards, write probes, redacted logs, dry-run coverage, and
package-specific wheel/source policy.

Its ArcGIS Pro registry discovery, conda environment copying/relocation, Esri paths, ArcPy/GDAL
verification, Pro-version naming, and map-picker WebView2/pythonnet constraints are backend- or
application-specific and are not part of the generic uv architecture.

## Tests

```console
python -m pytest
```

Synthetic repositories cover standardized metadata, requirements-only projects, Tkinter, native
dependencies, external executables, repository resources, secret environment variables, protected
paths, archive traversal, reports, and the target application's important deployment shape. Tests
do not make live OpenAI API calls or execute target code.

## Limitations and roadmap

- Online PyPI and Windows-wheel inspection is explicit (`plan --online`) and covers core plus
  explicitly selected optional dependencies. A present `uv.lock` is statically traversed for the
  selected Windows/Python/extra graph and locked wheel/source-distribution policy.
- Private GitHub repositories are out of scope for the MVP.
- Current generation is focused on the two source-mode reference applications. General package
  deployment and a complete offline Python/package bundle remain future work.
- Structural generation validation is not a substitute for provisioning and exercising the kit
  on a fresh Windows Standard User account. That runtime and GUI evidence belongs to Milestone 4.
- Offline deployment is an architectural extension point, not the initial delivery mode.
