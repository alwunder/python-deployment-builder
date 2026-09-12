# PR #9: omitted project fields and files(package=...)

Starting head: `bd5ea6081a0337c89d90ffdf14244a51a5458db1`.
Exact-head review: `2026-09-11T23:20:26Z`.

| P2 finding | Thread | Comment |
| --- | --- | --- |
| Treat omitted dependencies as an authoritative empty field | PRRT_kwDOT9hvCc6hqtuf | 3994149075 |
| Suppress legacy entry points when static groups are omitted | PRRT_kwDOT9hvCc6hqtui | 3994149079 |
| Resolve the compatible files(package=...) spelling | PRRT_kwDOT9hvCc6hqtuj | 3994149081 |

Pre-next-review accounting: 118 findings/comments, 115 unresolved inline threads,
three review-level-only findings, one NOT_APPLICABLE inline finding. No historical
thread resolution, review dismissal, or merge belongs to this correction.

## Reproduction before production changes

Eleven initial regression cases failed against the starting head: omitted
dependencies with both legacy sources, four omitted console/GUI legacy launcher
cases, a stale setup.py python_requires constraint, and four files(package=...)
binding forms. Eight additional dynamic script-group cases failed before the
new conservative blocker was implemented.

`scripts/verify_omitted_metadata.py` builds fourteen disposable synthetic projects
with the exact pinned uv 0.12.5 and setuptools 79.0.1. The script runs uv lock and
isolated uv build --wheel with Python 3.12, records actual lock/wheel metadata, and
asserts post-correction outcomes. Successful wheels report Generator:
`setuptools (79.0.1)`. Generated projects, wheels and environments are outside the
repository; acceptance repositories are never built or modified by this script.

| Shape, tested with setup.cfg and literal setup.py | Actual pinned result | Starting-head PDB result |
| --- | --- | --- |
| Existing project; dependencies/scripts/gui-scripts omitted; stale install_requires and both launchers | Lock contains demo only; no Requires-Dist or entry_points.txt | Retains obsolete and both stale launchers; false RUNTIME_SYNC_METADATA_UNSUPPORTED |
| Dynamic-only scripts or gui-scripts | Lock succeeds; tested wheel emits neither legacy launcher | Retains both groups without a blocker |
| Static plus dynamic scripts or gui-scripts | uv lock succeeds; setuptools build rejects simultaneous static/dynamic field | Merges static and stale legacy launchers without a blocker |
| Omitted requires-python plus legacy python_requires <3.10 | uv lock ignores legacy constraint; setuptools build crashes clearing it (NoneType error) | setup.py constraint is adopted and prevents Python policy selection |
| Omitted optional-dependencies plus legacy extras_require | Lock contains demo only; wheel has no optional requirement | No legacy extras merged; no corresponding PDB defect |

The requires-python experiment is not a successful wheel-build claim: the pinned
backend has its own clearing-field failure. The proven PDB defect is borrowing a
non-authoritative legacy constraint and rejecting Python selection even though
the standardized lock does not impose that constraint.

## Authority and bounded audit

The current [PyPA pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
distinguishes no project table from an existing project whose optional metadata is
not dynamic. Absence of an optional, non-dynamic field under an existing project
is authoritative absence. Static list/table entries may also coexist with dynamic
append-only extensions; pinned backend capabilities must be established separately.

`project_table_present` is now separate from field presence. Dependencies and each
launcher group are statically authoritative when that table exists and the
corresponding field is not dynamic. This covers omitted, explicit empty, and
explicit nonempty fields. Dependency key presence is still used for type checking,
not authority. Malformed dependency/dynamic values still fail controlled.

Only overridden fields are suppressed. Legacy files remain provenance and
packaging-surface inputs. No-project legacy dependencies retain the existing
RUNTIME_SYNC_METADATA_UNSUPPORTED blocker; no-project legacy launchers remain
available. Dynamic dependency evidence and the preceding conservative dependency
blocker are unchanged.

| Audited field | Omission under existing project | Legacy refill / dynamic outcome |
| --- | --- | --- |
| dependencies | Empty when non-dynamic | Corrected both legacy sources; dynamic evidence retained and blocked conservatively |
| scripts | Empty when non-dynamic | Corrected console_scripts only; dynamic evidence retained |
| gui-scripts | Empty when non-dynamic | Corrected gui_scripts independently; dynamic evidence retained |
| name | Required static identity, not a meaningful optional empty value | Existing explicit identity guards unchanged; no general malformed-project validator introduced |
| version | Required static or dynamic identity, not a meaningful optional empty value | Existing explicit-value and bounded dynamic-version logic unchanged |
| requires-python | No standardized Python constraint when omitted/non-dynamic | Corrected setup.py/Pipfile refill; setup.cfg path also guarded. No-project and existing dynamic fallback behavior retained |
| optional-dependencies | No standardized optional groups when omitted/non-dynamic | PDB does not merge legacy extras_require into this field, so no refill correction needed; selected extras unchanged |

Generic project.entry-points custom groups are not modeled as console/GUI
launchers. No custom-group parser, suppression rule or new API family was added.

Because the tested pinned backend cannot reliably materialize dynamic launcher
groups, transient inspection evidence now emits ENTRYPOINT_METADATA_UNSUPPORTED.
Both dynamic-only and static+dynamic forms keep inspectable launcher evidence but
cannot be represented as a proven deployment. Dry-run reports the blocker and
generation stops before uv acquisition, lock preparation or output writes. The
existing static groups still win over conflicting legacy targets. Focused tests
also validate a correct console-entry application wheel with a stale omitted GUI
group present in either legacy source.

Two previous test assumptions were deliberately corrected, not preserved as false
contracts: an omitted dependency field under project is not legacy-owned, and an
omitted second launcher group is not implicitly dynamic. Coverage now explicitly
distinguishes no-project, static-empty and dynamic group behavior.

## Resource spelling and target evidence

`scripts/verify_files_keyword.py` creates a disposable package and probes actual
selected interpreters. Python 3.11.16 was acquired in uv's managed cache for this
test; the configured PyCharm SDK was not changed.

| Interpreter | files('app') | files(package='app') | files(anchor='app') | files() inside package module |
| --- | --- | --- | --- | --- |
| Python 3.11.16 | Works | Works, no warning | TypeError | TypeError |
| Python 3.12.14 | Works | Works, DeprecationWarning | Works | Works |
| Python 3.13.7 | Works | Works, DeprecationWarning | Works | Works |

The policy order remains 3.12, 3.13, 3.11, 3.14. The
[Python 3.14 documentation](https://docs.python.org/3.14/library/importlib.resources.html#importlib.resources.files)
also retains package= compatibility with a warning. No target-policy or schema
change is necessary for this spelling. Analysis is not a universal cross-version
API validator: existing anchor= and implicit-caller recognition is not a claim
that those forms execute on Python 3.11.

One bounded branch selects position zero or the single recognized anchor/package
keyword through call_argument. Positional wins a single duplicate binding;
conflicting anchor plus package, unknown keywords, **kwargs, and extra positional
arguments remain unresolved. Only no arguments and no keywords select the
implicit caller. Explicit values use the existing package-anchor resolver.

The exact pre/post staged-source experiment used the starting-head resolver and
the corrected resolver against the same disposable source: before correction the
resource was not staged and launching raised FileNotFoundError; after correction
it was staged and the read returned `{}`. Tests cover module/direct aliases,
static variable resolution, unresolved dynamic values, custom roots, exact and
parent package-dir mappings, traversal rejection, role-aware staging and normal
release secret scanning. Existing containment, symlink, modern/legacy resource
and pkgutil paths are unchanged. The existing three-call resource-evidence test
now expects three pieces of evidence rather than two.

## Acceptance and schemas

Read-only comparisons against inspect_metadata from the exact starting SHA prove
that all three repositories retain identical dependency and entry-point records,
including provenance. Their Git status is unchanged.

| Repository | Unchanged SHA | Contract |
| --- | --- | --- |
| SimpleGeorefGUI | f484570d89fb1f9e9170fac915475358dfc1234e | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python, 77 package-data members |
| Geo Map Explanation Extractor | 5e7b321d0aeb9ba1d586bfc548c79793d84c6033 | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | e1e7a1588c37a99c2d02efaf3eef3d04636f12f0 | source / SOURCE_COMPATIBLE; existing kit STATIC_VALID |

SGG retains its explicit GUI entry
`simple-georef-gui = simple_georef_gui_app.georef_main:main`; its omitted console
group gains nothing from legacy configuration. Geo retains both standardized
console entries. TN retains its standardized console and GUI entries, and the
existing kit's reviewed proxy-tools==0.1.0 artifact is unchanged. No new runtime
acceptance execution is claimed for these repositories.

ANALYSIS_SCHEMA_VERSION stays 1.4; PLANNING_SCHEMA_VERSION stays 1.3. The launcher
evidence list is a transient MetadataResult field. A new precise risk-code value
uses the existing risk model and does not add persisted model fields.

## Quality

The single complete-suite run passed: **1249 passed, 3 skipped in 292.23 seconds**,
up 74 from the 1175-pass baseline. Ruff and `git diff --check` pass. Final diff
inspection covers only the four production files, four regression-test files,
two synthetic verification scripts, and this report. No wheels, kits, temporary
projects, managed environments, or acceptance artifacts are committed.

The full suite retains approved root-extra separation, approved-path uniqueness,
legacy resource keywords, environment aliases, structural lock-root policy,
dynamic imports, pkgutil keywords, MANIFEST/include-package-data guards, exact
sync arguments, reverse artifact completeness, mode-aware pip checks, entry-point
extras, short-secret and LOCALAPPDATA behavior, wheel policies, dependency proofs,
security/provenance, rollback, and deterministic packaging.
