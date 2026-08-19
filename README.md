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

Milestone 1 static assessment is implemented. The CLI exposes the complete lifecycle command
shape, while `plan`, `generate`, `validate`, and `all` currently stop with an explicit milestone
message rather than pretending to perform work.

```powershell
python -m pip install -e ".[dev]"
pdbuilder assess C:\path\to\repository
pdbuilder assess https://github.com/owner/public-repository
```

By default, assessment reports are written beneath
`./pdbuilder-output/<application-id>/`. Choose a specific location with `--output-dir`:

```powershell
pdbuilder assess ..\geo-map-exp-extractor `
  --output-dir artifacts\geo-map-exp-extractor
```

The result is:

```text
assessment.json   stable, typed automation input
assessment.md     developer-readable evidence and recommendations
```

## Lifecycle and architecture

The implementation is divided into focused layers:

- `analysis`: safe repository materialization, packaging metadata, AST imports, resources,
  configuration, runtime assumptions, writes, dependencies, and risk rating;
- `planning`: policy decisions made from assessment facts, including Python/runtime selection and
  source-versus-package deployment (Milestone 2);
- `backends`: runtime protocol plus the first `uv_managed` implementation (Milestone 2 onward);
- `generation`: Windows bootstrap, launcher, repair, diagnostics, metadata, and templates
  (Milestone 3);
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

Generated deployments will use paths under `%LOCALAPPDATA%\PythonDeploymentBuilder`, exact
executable paths, and no machine or user PATH edits. They will not request elevation, modify system
Python, write to Program Files, weaken TLS/security controls, or attempt to bypass organizational
policy. A policy block will be reported plainly.

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

## Findings for the first reference application

`geo-map-exp-extractor` is the first acceptance application. Its current static assessment is
stored in [artifacts/geo-map-exp-extractor](artifacts/geo-map-exp-extractor) and rates it YELLOW:
likely deployable, with issues requiring deliberate planning.

The repository has standard metadata, a `src/` layout, Python `>=3.11`, CLI and GUI entry points,
Tkinter, and matched declared imports. It also deliberately relies on repository-adjacent
`profiles/`, `prompts/`, `README.md`, and `examples/`; derives the repository root from `__file__`;
and writes its default outputs/cache beneath the repository. It has no `uv.lock` yet.

Those facts favor an initial source-based deployment with the environment stored elsewhere under
LocalAppData. That is a planner decision, not a special case embedded in the analyzer. The
application's session `Set API key...` workflow can remain unchanged, and deployment/validation
must not require or expose an API key.

## SimpleGeorefGUI lessons

SimpleGeorefGUI and its deployment-hardening PR #63 inform generic behavior: per-user state, exact
runtime invocation, metadata/fingerprint stale detection, fast routine checks, deeper diagnosis,
scoped repair with rollback and deletion guards, write probes, redacted logs, dry-run coverage, and
package-specific wheel/source policy.

Its ArcGIS Pro registry discovery, conda environment copying/relocation, Esri paths, ArcPy/GDAL
verification, Pro-version naming, and map-picker WebView2/pythonnet constraints are backend- or
application-specific and are not part of the generic uv architecture.

## Tests

```powershell
python -m pytest
```

Synthetic repositories cover standardized metadata, requirements-only projects, Tkinter, native
dependencies, external executables, repository resources, secret environment variables, protected
paths, archive traversal, reports, and the target application's important deployment shape. Tests
do not make live OpenAI API calls or execute target code.

## Limitations and roadmap

- Online package-index and Windows-wheel inspection is not yet implemented.
- Python-version selection belongs to Milestone 2 and is not guessed by assessment.
- No deployment files are generated yet.
- Private GitHub repositories are out of scope for the MVP.
- Windows runtime tests, pinned uv bootstrap/checksum policy, frozen lock sync, fast launch,
  repair, and diagnostics arrive in Milestones 2–4.
- Offline deployment is an architectural extension point, not the initial delivery mode.
