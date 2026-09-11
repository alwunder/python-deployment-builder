# PR #9: standardized dependency-field authority

Starting head: `40da08522463fc8992d698cf8b187a3e59706270`.
Exact-head review submitted: `2026-09-11T15:17:07Z`.

P2: **Ignore legacy dependencies overridden by [project]**.
Thread: `PRRT_kwDOT9hvCc6hhp8n`; comment: `3990594314`.
Pre-next-review accounting: 115 findings, 112 unresolved inline threads,
three review-level-only findings, one NOT_APPLICABLE inline finding.
No thread resolution, review dismissal, or merge is authorized by this correction.

## Failing reproduction and field-level correction

Regression tests were added before production changes. Static nonempty and empty
PEP 621 dependency fixtures with stale setup.cfg or literal setup.py requirements
failed: assessment retained obsolete, selected_dependencies included it, and
planning added RUNTIME_SYNC_METADATA_UNSUPPORTED despite a lock excluding it.
Equivalent legacy requirements polluted authoritative evidence; conflicting
requirements contributed stale evidence instead of being ignored at ingestion.

Inspection now distinguishes key presence from truthiness. A valid dependencies
list is authoritative only when present and not listed in project.dynamic.
Explicit [] is present. An invalid list type or non-string member raises a
controlled ValueError before any legacy fallback. Malformed dynamic declarations
also fail rather than changing the field's authority accidentally.

For authoritative static dependencies, only install_requires ingestion from
setup.cfg and setup.py is suppressed. Both files remain metadata/provenance and
packaging-surface inputs; package/module selection and unrelated supported fields
are still read. A retained standardized dependency has exactly pyproject.toml
evidence with detail `Declared in [project].dependencies.` Neither equivalent nor
conflicting legacy constraints are merged into it.

Absent/dynamic dependencies do not receive the override. Genuine setup.cfg-only
and setup.py-only runtime dependencies still trigger the existing blocker.
The planner's backend-only filter is unchanged; corrected metadata now makes its
input meaningful. Optional dependency groups and entry-point-extra requirements
are unaffected, including the distinction between unselected and selected extras.

## Pinned toolchain evidence

`scripts/verify_dependency_authority.py` creates disposable local synthetic modern
and obsolete wheels and ten projects (five shapes for each legacy file type).
It runs actual isolated builds with setuptools 79.0.1 and:

```text
uv 0.12.5 (210d1f678 2026-08-14 x86_64-pc-windows-msvc)
uv lock --python 3.12 --find-links <temporary-input-wheels>
uv build --wheel --python 3.12 --out-dir <temporary-project>/dist
```

The wheel Generator field confirms setuptools 79.0.1. The script asserts lock,
wheel, assessment, and plan results. It executes only explicitly created synthetic
build fixtures, not acceptance applications. Generated projects/wheels remain
outside the repository and are not committed.

| Project dependency shape | Actual uv lock | Actual wheel / build | Corrected PDB |
| --- | --- | --- | --- |
| Static modern>=1 | demo + modern; obsolete absent | Requires-Dist: modern>=1 | modern only; no false blocker |
| Static [] | demo only | No Requires-Dist | Empty runtime set; no false blocker |
| Static modern + dynamic dependencies | Lock fails | setuptools rejects simultaneous static/dynamic field | Retain evidence; RUNTIME_SYNC_METADATA_UNSUPPORTED |
| Dynamic-only with legacy obsolete>=1 | demo + obsolete | Requires-Dist: obsolete>=1 | Retain obsolete; existing conservative M6.1 blocker |

The current [PyPA pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
allows static list/table entries together with dynamic append-only extension.
This must not be confused with the observed capabilities of setuptools 79.0.1:
that pinned backend rejects the simultaneous dependency shape, so no reliable
appended-dependency lock contract exists for it. PDB does not treat the static
subset as complete. A transient MetadataResult evidence list emits the existing
blocking risk even when legacy declarations duplicate the static requirement or
no literal backend additions can be inspected. Dry-run exposes the blocker;
generation stops before uv acquisition or output creation.

Dynamic-only deserves a separate qualification: uv 0.12.5 can call the backend and
lock its supplied dependencies in this experiment. It is not accurate to claim uv
never reads legacy requirements. This correction preserves M6.1's requested
conservative treatment rather than introducing backend execution or a new dynamic
metadata proof into production assessment.

## Bounded core-field precedence audit

| Modeled field | Audit result |
| --- | --- |
| name | Existing standardized-value guards prevent stale legacy override; unchanged |
| version | Existing standardized-value guards prevent stale legacy override; unchanged |
| requires-python | Existing standardized-value guards prevent stale legacy override; unchanged |
| dependencies | Ingestion now obeys present-and-not-dynamic authority |
| scripts / gui-scripts | One adjacent launcher defect reproduced and corrected at group level |

The launcher reproduction declares a standardized console entry app:main and an
explicit empty project.gui-scripts table, with obsolete=old:main in legacy GUI
entry points. Both pinned builds contain only the standardized console launcher.
Before correction PDB preferred the stale GUI target old:main. Now the static
standardized group suppresses only its corresponding legacy group, including
explicit empty tables. Other groups and dynamically extensible groups are not
silently declared overridden. Tests cover console/GUI groups, empty/nonempty
tables, both legacy sources, and preservation of the other group. No full metadata
precedence engine or extras redesign was added.

## Acceptance and compatibility

All three repositories were assessed read-only. Their metadata dependency objects
(including constraints and evidence) were compared against inspect_metadata from
the exact starting commit and are identical. Git status before/after is unchanged.

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | f484570d89fb1f9e9170fac915475358dfc1234e | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python, 77 package-data members |
| Geo Map Explanation Extractor | 5e7b321d0aeb9ba1d586bfc548c79793d84c6033 | source / SOURCE_COMPATIBLE; nine dependency records, all pyproject provenance |
| TN Coordinate Converter | e1e7a1588c37a99c2d02efaf3eef3d04636f12f0 | source / SOURCE_COMPATIBLE; six dependency records unchanged |

TN's existing `pdb-m61-regression-20260901/tn-kit` is STATIC_VALID with reviewed
proxy-tools==0.1.0 (`proxy_tools-0.1.0-py3-none-any.whl`) unchanged.
Geo's seven selected runtime names and constraints also exactly match its static
project.dependencies list; the nine total records include unselected groups.
Geo and TN assessment-only plans retain their existing pending lock-currentness
verification; this correction does not claim a new runtime acceptance run.

No persisted fields were added. ANALYSIS_SCHEMA_VERSION stays 1.4 and
PLANNING_SCHEMA_VERSION stays 1.3. The new evidence list is transient inspection
state feeding an existing risk code and existing generation guard.

## Quality

Fifty new focused regression cases pass. The single complete-suite run reports
**1175 passed, 3 skipped in 252.32 seconds**, up from 1125 passed, 3 skipped.
Ruff and `git diff --check` pass. Final diff inspection found only the two
production analysis files, focused regression tests, the synthetic toolchain
verifier, and this evidence report. No generated acceptance/build artifacts are
included.

The full suite preserves the prior approved-extra edge-context separation,
approved path uniqueness, legacy resource keywords, alias-aware environment reads,
lock-root guards, dynamic imports, pkgutil handling, MANIFEST/package surfaces,
sync contract, reverse approved-artifact completeness, mode-aware pip checks,
entry-point extras, short-secret/LOCALAPPDATA behavior, wheel policies and
dependency proofs, resource/inventory analysis, provenance, rollback, and
deterministic packaging. Persisted schema constants are unchanged.
