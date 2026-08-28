# Python Deployment Builder

Python Deployment Builder is a developer-side tool for turning a Python repository into a
repeatable, non-admin Windows deployment. It separates repository analysis from deployment
policy and keeps the generated end-user kit independent of the builder itself.

```text
Python Deployment Builder (developer machine)
        assess -> plan -> developer preparation -> generate -> validate -> package
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

Milestones 1 through 6 are implemented for the Windows uv-managed path: scoped static assessment,
explicit deployment planning, authorized developer preparation, PowerShell-free generation,
non-executing kit validation, explicit developer-side runtime validation, and deterministic
release packaging. Milestone 6 adds role-aware analysis, evidence-backed structural guidance,
diagnostic entry-point candidates, and useful incomplete plans when generation is blocked. The Windows
`uv_managed` backend is **pilot ready** for applications within the currently supported
source-deployment shape. Two materially different applications have passed real Windows Standard
User testing:

1. [Geo Map Exp Extractor](docs/acceptance/geo-map-exp-extractor-2026-08-20.md), a `src`-layout
   application with repository-adjacent resources and a session API-key workflow;
2. [Tennessee Coordinate Converter](docs/acceptance/tn-coordinate-converter-2026-08-24.md), a
   flat-module desktop GIS utility with an optional map extra, Python.NET/WebView2, an approved
   source-only dependency artifact, and an argparse-based GUI entry point.

This is evidence that the backend generalizes beyond one application shape, not proof of universal
Windows compatibility. Each new desktop application still requires its own manual GUI and
organizational-environment acceptance evidence.

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
pdbuilder validate C:\staging\deployment-kit --static
pdbuilder validate C:\staging\deployment-kit --runtime
pdbuilder validate C:\staging\deployment-kit --runtime --dry-run
pdbuilder package C:\staging\deployment-kit
pdbuilder package C:\staging\deployment-kit --dry-run
pdbuilder all C:\path\to\repository --online
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

- `analysis`: safe repository materialization, role/ignore-aware inventory, packaging metadata,
  scoped AST imports, resources, configuration, runtime assumptions, writes, entry-point
  candidates, existing deployment/vendor-runtime evidence, structural guidance, and risk rating;
- `planning`: policy decisions made from assessment facts, including Python/runtime selection,
  selected optional features, explicit PyPI wheel inspection, locked transitive artifact policy,
  external runtimes, platform treatment, readiness gating, and source-versus-package deployment;
- `backends`: runtime protocol plus the first `uv_managed` implementation;
- `generation`: verified pinned-uv acquisition, explicit lock preparation, approved-wheel checks,
  collision-safe staging, manifests, CMD bootstrap, standalone runtime helpers, fast launch,
  scoped repair, diagnostics, logging, redaction, and structural validation;
- `validation`: static kit integrity/security checks by default and explicitly opted-in isolated
  runtime provisioning, imports, fast-path, staleness, rollback, repair, and diagnostics;
- `packaging`: deterministic ZIP creation, checksum and provenance reports, safe extraction,
  extracted-package validation, and evidence-driven human smoke-test handoff;
- `reporting`: schema-versioned JSON and companion Markdown at every stage.

Assessment describes evidence; planning chooses policy. For example, an assessment may establish
that Python 3.12 and 3.13 satisfy repository and dependency evidence, while a policy selects 3.12
for a particular release. This boundary allows future policies to reuse the same assessment.

### Analysis scope and structural guidance

Assessment classifies repository paths as application source, runtime resources, mutable-state
candidates, deployment support, tests, documentation, examples/snippets, development tooling,
ignored/local material, or unknown. Only application source contributes normal production import,
runtime, subprocess, configuration, and path findings. Root and nested `.gitignore` files use
gitwildmatch rules relative to their containing directories; this analysis does not require Git or
a `.git` directory. Stronger production import/resource evidence promotes normally excluded
docs/example/deployment paths. An ignored file explicitly referenced by application source remains
excluded and is surfaced as a blocker, while an ignored state/session/cache file with static write
evidence is described as mutable local state rather than an immutable package resource.

The assessment repository fingerprint identifies deployment inputs: scoped application source,
statically detected immutable runtime resources, and project/dependency/lock/ignore metadata. It is
not a whole-working-tree identity, a Git commit, or a staged-kit hash. Changes confined to excluded
tests, documentation, examples, ignored/local files, or deployment support do not change it unless
stronger runtime evidence promotes the path. Generation records this assessment fingerprint as
provenance; generated-file hashes independently protect every staged kit file. Analysis roles do
not themselves decide which repository files source-mode generation copies.

Guidance is typed as `GOOD_PRACTICE`, `WORKS_BUT_IMPLICIT`, `IMPROVEMENT_OPPORTUNITY`,
`APPLICATION_SPECIFIC`, `PDB_LIMITATION`, or `GENERATION_BLOCKER`. Each item explains its evidence,
why it matters, and a direction only when justified. Existing launch, repair, diagnostic, and
environment scripts are inventoried separately; their imports do not become application launch
requirements.

AST-discovered `__main__` launchers are diagnostic entry-point candidates only. Standardized
project/setup/Poetry entry-point metadata remains authoritative. A likely legacy launcher helps a
developer understand the repository, but PDB does not execute it or silently make it deployable.

`pdbuilder plan` writes an incomplete but useful JSON/Markdown plan even when an authoritative
entry point is missing. The command returns nonzero, records `BLOCKED_PENDING_ENTRYPOINT`, and
continues to expose every safely detectable blocker, including a missing lockfile. `--online` can
inspect known legacy requirements and deployment-support constraints informationally without
treating them as selected dependencies, installing packages, or building source distributions.
The readiness state is a primary summary (risk gate, entry point, selected developer artifact,
lockfile, then verification), while `blocker_codes` and reports retain all detected blockers.
Generation and `all` still require an authoritative entry point and all normal readiness gates.

Assessment and planning JSON use the current 1.1 output schema. Commands analyze a repository and
construct current models; they do not load arbitrary historical assessment/plan JSON as workflow
inputs. Deployment-kit and release manifests have separate schemas and compatibility checks.

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

Runtime validation is a separate `--runtime` operation because installing dependencies and
importing target modules crosses this trust boundary. `pdbuilder validate <kit>` remains static by
default.

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

The intended source-control workflow is to create a deployment-preparation branch, assess and
plan, explicitly prepare missing metadata, generate outside the repository, validate the staged
product, and then review the repository diff. A verified `uv.lock` is a reasonable source-control
candidate but is not required to be committed before the staged kit can work. Bundled `uv.exe`,
duplicated source, rendered launchers/helpers, manifests, approved wheels, runtime state/logs, and
distribution ZIPs normally remain generated output outside source control. The builder never
commits or pushes target-repository changes.

A future dedicated `pdbuilder prepare` command may formalize repository preparation.

### Repository defaults

An optional committed `pdbuilder.toml` can capture a deliberately small set of recurring defaults:

```toml
[pdbuilder]
architecture = "x86_64"
bootstrap = "bundled_uv"
system_certs = true
extras = ["map"]
```

CLI values override configuration. Missing configuration preserves the established defaults.
Unknown sections, keys, types, and policy values fail clearly. Credentials, approved-wheel paths,
developer output paths, and per-user runtime paths do not belong in this file; approved artifacts
remain explicit command inputs.

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

## Validating and packaging a kit

Static validation parses the staged manifest and generated-file index, verifies every recorded
hash, metadata/lock/source roots, entry-point structure, extras and approved artifacts, and scans
the generated deployment layer for forbidden PowerShell, permanent PATH changes, Program Files
writes, developer paths, and secret material. It writes schema-versioned
`validation-report.json` and `validation-report.md` beside the kit by default.

Runtime validation must be explicitly requested. It uses an isolated validation LocalAppData
root, runs the kit's bundled uv, provisions its selected managed Python, performs the generated
locked/no-build setup, executes helpers with `-B -E -s`, imports selected dependencies and the entry
module, verifies no development dependencies were installed, and exercises fast state,
controlled staleness, rollback, repair scope, and diagnostics. It never calls a paid API and does
not launch the GUI. The isolated runtime root and logs are retained with the report for review.
The generated `launch.py --check` operation verifies only that the source module imports and its
planned callable exists; it deliberately does not execute an arbitrary GUI entry point. Synthetic
subprocess tests exercise the separate invocation contract, including isolation of deployment-helper
arguments from application `sys.argv` and file-based reporting of early launch failures.

`pdbuilder package <deployment-kit>` first requires `STATIC_VALID`, then creates a deterministic
ZIP of the kit contents so Run, Repair, and Diagnose remain at archive root. Stable ordering,
timestamps, permissions, and path syntax mean identical kit bytes and package inputs produce an
identical ZIP SHA-256. Packaging also writes a portable checksum, schema-versioned
`release-manifest.json`, companion Markdown, and a generic evidence-driven `SMOKE-TEST.txt`.
It safely extracts the new ZIP and requires a second `STATIC_VALID` before reporting
`READY_FOR_MANUAL_ACCEPTANCE`. Package output defaults beside, never inside, the kit.
Release ZIP SHA-256 values use uppercase hexadecimal consistently in the manifest and portable
`<SHA256>  <filename>` checksum file.
The release manifest, checksum, Markdown report, and smoke test are sidecars in the distribution
directory; they are never members of the ZIP whose hash they describe. The release-manifest
timestamp records the packaging event and may vary between runs, while the ZIP excludes that
timestamp and remains deterministic. Source revision and assessment repository fingerprint are
propagated only from the deployment manifest recorded during generation; packaging never infers
provenance from its current directory or a later Git checkout.

```console
pdbuilder package C:\staging\deployment-kit --version 1.0.0
```

The explicit version is required only when the deployment manifest has no trustworthy version.
`--dry-run` validates and previews filenames, inputs, manifest fields, and output paths without
writing, extracting, or mutating anything. Packaging is not application acceptance and does not
publish a GitHub Release. A human must complete the generated smoke test before external
publication.

`pdbuilder all <repository>` orchestrates assess, plan, generate, static validate, and package via
the same lifecycle functions. It stops with an actionable command at missing-lock and unsupplied
approved-artifact boundaries. It never creates a lock silently. Runtime validation is omitted
unless `--runtime-validation` explicitly crosses the existing execution boundary; selected extras
and approved wheels remain explicit/configured policy.

`bundled_uv` removes the bootstrap dependency on `curl.exe`, `tar.exe`, and `certutil.exe`, but the
first setup still needs permitted HTTPS access for managed Python and locked packages unless a
future offline bundle or suitable organizational cache is supplied. `--system-certs` uses Windows
trust roots; it does not bypass proxy, firewall, or certificate policy.

## Reference applications

`geo-map-exp-extractor` is the first acceptance application. Its static assessment is
stored in [artifacts/geo-map-exp-extractor](artifacts/geo-map-exp-extractor) and rates it YELLOW:
likely deployable, with issues requiring deliberate planning.

Its generated Windows deployment passed fresh Standard User provisioning without elevation,
PowerShell, or preinstalled Python, followed by GUI/resource, live API workflow, fast-launch,
diagnostic, repair, update/staleness, and copied-project portability testing. The two-round manual
test history and exact source/runtime traceability are recorded in the
[2026-08-20 acceptance report](docs/acceptance/geo-map-exp-extractor-2026-08-20.md).

The repository has standard metadata, a `src/` layout, Python `>=3.11`, CLI and GUI entry points,
Tkinter, and matched declared imports. It also deliberately relies on repository-adjacent
`profiles/`, `prompts/`, `README.md`, and `examples/`; derives the repository root from `__file__`;
and writes its default outputs/cache beneath the repository. Generation therefore requires an
explicit developer-prepared lock and emits a project write probe.

Those facts favor an initial source-based deployment with the environment stored elsewhere under
LocalAppData. That is a planner decision, not a special case embedded in the analyzer. The
application's session `Set API key...` workflow can remain unchanged, and deployment/validation
must not require or expose an API key.

`tn-coordinate-converter` began as the cross-project planner test and became the second real
accepted application. Its reports are stored in
[artifacts/tn-coordinate-converter](artifacts/tn-coordinate-converter). It uses flat modules, an
existing `uv.lock`, core `pyproj`, and an explicitly selected `map` extra while the `dev` extra is
excluded. The map feature adds `pywebview`, `pythonnet`, and `clr-loader`, uses Microsoft Edge
WebView2 and NGMDB MapView, and exposes a locked transitive source-only dependency:
`pywebview -> proxy-tools`.

The source distribution was reviewed and converted developer-side into an explicitly approved
pure-Python wheel. End-user synchronization remained locked and `--no-build`; Repair reused the
approved artifact deterministically. Standard User testing exercised conversion, Carter formats,
batch behavior, MapView, fast launch, Diagnose, Repair, and an argparse-based GUI entry point. That
entry point exposed and led to a generic application-argument isolation and GUI failure-diagnostics
fix in the builder. The chronology and exact release traceability are recorded in the
[2026-08-24 acceptance report](docs/acceptance/tn-coordinate-converter-2026-08-24.md).

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
- The `uv_managed` backend is pilot ready, not universally compatible with every Windows Python
  application. Developer-side runtime validation is not a substitute for application-specific
  Standard User GUI, external-service, and organizational network-policy testing.
- Offline deployment is an architectural extension point, not the initial delivery mode.
- GitHub Release publication, signing, MSI/EXE wrappers, and automated acceptance are outside the
  packaging command. It produces reviewable release inputs, not a published or accepted release.
