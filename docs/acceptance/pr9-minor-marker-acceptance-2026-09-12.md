# PR #9: minor-marker proof and completed package acceptance

Starting remote/local HEAD: `4888ee28710d20dc8e45886ad4d928f0f556aa66`.
Branch: `milestone-6-1-generation-contract`. No acceptance repository was modified.

## Separate accounting

The pending correction contains **two Codex findings**, unchanged:

- P1: Reject undeclared executable members in application wheels
  (`PRRT_kwDOT9hvCc6hypCG`, comment `3997215864`).
- P2: Follow assigned Traversables when resolving resource reads
  (`PRRT_kwDOT9hvCc6hypCJ`, comment `3997215868`).

Two separately authorized, pre-existing acceptance issues complete their acceptance:

- `PRE_EXISTING_ACCEPTANCE_POLICY_FALSE_POSITIVE`: descriptive Core METADATA
  triggered the Program Files write heuristic. The path-context correction and
  original reproduction are recorded in
  [the policy report](pr9-security-content-context-2026-09-12.md).
- `PRE_EXISTING_MINOR_MARKER_PROOF_PRECISION_BLOCKER`: minor-invariant
  `python_full_version` markers were unnecessarily unprovable.

Neither acceptance issue is a new review finding. Accounting remains **127 total,
124 unresolved inline, three review-level-only, one NOT_APPLICABLE inline**.
The review-only findings remain historical #35, approved-wheel PEP 440 semantic
version comparison, and complete locked sync-command validation. The automatic
flat package plus loose module review premise remains NOT_APPLICABLE.

## Before-change proof

Two regressions were added and run before editing marker production code. Both
failed: `>=3.12` returned UNPROVABLE, and strict direct NumPy presence could not
be proven from the three SGG-shaped root edges. `>=3.12.1` was already
UNPROVABLE, correctly.

Executing the marker implementation read with `git show` from the exact starting
SHA independently reproduced both atomic UNPROVABLE results. This used trusted
repository implementation code, not target application code or a checkout/reset.

## Bounded proof implementation

`target_marker_applicability()` evaluates packaging's parsed marker AST. Ordered
release comparisons and equality/inequality use the existing
`minor_python_compatibility()` interval proof; no target patch is populated.
Equality can reuse the exclusion proof to establish disjoint exact versions.
Major/minor wildcard equality and inequality are supported. Patch-prefix
wildcards and pre/dev/post/local spellings remain conservatively unprovable in
this bounded bridge, as do `in`, `not in`, `~=`, and `===`.

Actual packaging 25.0 parsed `"3.12" <= python_full_version` as a literal on the
left, operator `<=`, and Variable on the right. Plain numeric comparisons invert
the six supported operators correctly. A wildcard on the left is not treated as
a wildcard specifier. No host `Marker.evaluate()` fallback is used.

AND groups return false if any term is false, true if every term is true,
otherwise unknown. OR returns true if any group is true, false if every group
is false, otherwise unknown. Nested parsed lists retain parentheses; AND
precedence is retained within each OR group. All 18 binary tri-state combinations
and distinguishing grouped/ungrouped expressions are covered.

At selected **3.12 / Windows x86_64**:

| Comparison on python_full_version | Proof |
| --- | --- |
| `>=3.12`, `<3.13`, `==3.12.*`, `!=3.11.*` | APPLIES |
| `<3.12`, `>=3.13`, `==3.11.*`, `!=3.12.*` | DOES_NOT_APPLY |
| `>=3.12.1`, `<3.12.1`, `<3.12.5`, `==3.12.0`, `!=3.12.0` | UNPROVABLE |

`implementation_version`, `platform_release`, and `platform_version` remain
unselected. They may participate in ordinary boolean dominance, but receive no
invented facts. All four Python policy minors have boundary/patch regressions.

## Actual SGG uv 0.12.5 graph

The unchanged SGG root entry was read directly from its TOML lock:

| Dependency/version | Root-edge marker | 3.12 proof |
| --- | --- | --- |
| numpy 2.2.6 | `python_full_version < '3.11'` | DOES_NOT_APPLY |
| numpy 2.4.6 | `python_full_version == '3.11.*'` | DOES_NOT_APPLY |
| numpy 2.5.2 | `python_full_version >= '3.12'` | APPLIES |
| pyproj 3.7.1 | `python_full_version < '3.11'` | DOES_NOT_APPLY |
| pyproj 3.7.2 | `python_full_version >= '3.11'` | APPLIES |

Running lock inspection with the starting marker implementation retained all
three NumPy and both pyproj versions. The corrected graph retains only NumPy
2.5.2 and pyproj 3.7.2. Removal occurs only for provably false branches.

Application and approved-wheel Requires-Dist regressions both prove invariant
edges, still reject incompatible possible versions, still reject patch-sensitive
requirement/presence markers, and retain both sides of a `<3.12.5` / `>=3.12.5`
fork. A separate unconditional edge does not bless an incompatible possible
version. Existing artifact-fork and requested-extra proofs remain in the full
regression suite; their implementation was not changed.

## SGG acceptance, now completed

Source: `f484570d89fb1f9e9170fac915475358dfc1234e` (unchanged and clean).
Without artifacts: package / ENTRYPOINT_REQUIRES_PACKAGE_MODE /
BLOCKED_PENDING_APPLICATION_WHEEL. The map-extra flow separately needs its
reviewed proxy-tools artifact before generation, as before.

- Source surface: **13 Python + 77 package-data = 90 authoritative members**.
- GUI target: `simple_georef_gui_app.georef_main:main`, unchanged.
- Accepted application wheel SHA-256:
  `e479d668a59e879bbc42ee3d32ffcc89ce3bf40dc65d6c52d703be44703ede03`.
- Accepted proxy-tools 0.1.0 wheel SHA-256:
  `2431971dbca4cf6524f851bf7f9d9e3275ef64f0c5607ad39b348df05ff97bc5`.
- Descriptive METADATA passes; ordinary metadata secret/security scanning remains
  active. The 90-member source-derived list exactly matches the manifest; no
  unexpected Python or startup-active destinations were accepted.
- Generation succeeds; static validation is **STATIC_VALID**.
- Runtime provisioning used uv **0.12.5** and managed Python **3.12.14**.
  The plan still selects only the minor **3.12**; the installed patch is an
  observation, not an input to marker proof.
- Every automated runtime check passed: pinned uv, managed Python, helper sibling
  imports, locked/no-build setup, application-wheel installation, selected
  dependency imports, dev dependency exclusion, configuration isolation, fast
  path, controlled staleness, rollback, repair scope, and diagnostics.
- An additional isolated `-I -B` probe imported the authoritative GUI module from
  managed `env/Lib/site-packages/simple_georef_gui_app/georef_main.py`, observed
  NumPy 2.5.2 and pyproj 3.7.2, and confirmed no ArcPy/osgeo modules or
  ArcGIS/GDAL/osgeo/ArcPy/ArcGIS Pro runtime paths.
- Final automated state: **MANUAL_GUI_VALIDATION_REQUIRED**. No unattended GUI
  launch is presented as manual visual acceptance.

Disposable output: sibling `pdb-m61-minor-marker-acceptance-20260912`, with
`static.json`, `runtime.json`, `managed-import.json`, and two package directories.
The isolated runtime is `C:/pdb-m61-sgg-0912`. None is committed.

Both new ZIPs are byte-identical; both extracted kits validate STATIC_VALID.
`SimpleGeorefGui-Windows-v1.3.zip` is **21,011,577 bytes**, with new SHA-256:

`69AE1EE3EC8169291F265ACEAE57BEC46035A15EB99D6BD3848C3A5910D6C05B`

This supersedes the historical `FDCA6A5A...` hash: the required application
surface changed package-mode manifest/fingerprint bytes. The accepted wheel
bytes and SGG source did not change.

## Source-mode acceptance

- Geo: `5e7b321d0aeb9ba1d586bfc548c79793d84c6033`, unchanged;
  **source / SOURCE_COMPATIBLE**, no application artifact.
- TN: `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0`, unchanged;
  **source / SOURCE_COMPATIBLE**. Its existing
  `pdb-m61-regression-20260901/tn-kit` remains **STATIC_VALID**, retaining reviewed
  **proxy-tools==0.1.0**.
- SGG, Geo, and TN assessment dependencies, entry points, configuration evidence,
  and resources compare unchanged against starting-head analysis. The expected
  marker-driven graph narrowing is separate from source assessment.

## Contract and verification

Analysis/planning schemas remain **1.4 / 1.3**. No marker/policy field is persisted.
The unreleased M6.1 package-only ApplicationArtifact contract requires a nonempty
source-derived authoritative member list and fingerprints it; source manifests
without application artifacts retain compatibility. Deployment envelope version
remains 1.0; no insecure default is added for unpublished package artifacts.

Focused marker tests: **80 passed**. Broader planning/generation/approved-edge
subset: **712 passed, 3 skipped**.

One final complete suite: **1933 passed, 4 skipped** in 348.18 seconds. This
includes all 86 application-surface/assigned-Traversable tests, all 52
content-context policy tests, and all 80 new marker tests. The previous 1801-pass
baseline is not presented as the final count.

Ruff and `git diff --check` pass. Final diff inspection contains only the two
review corrections, two authorized acceptance corrections, their regression
coverage, and scoped text evidence. Generated wheels, kits, environments, and
ZIPs remain outside the commit. The three acceptance repositories remain clean.

The single acceptance-completing commit may now be pushed and receive exactly
one fresh exact-head review after PR Quality and the stale SGG hash are updated.
No historical thread is resolved; no review is dismissed; PR #9 is not merged.
