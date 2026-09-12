# PR #9: approved-extra context, artifact paths, legacy resource keywords

Starting head: `bc682d75b5d77580d5e76b7f17c3a375843368fe`.
Exact-head review submitted: `2026-09-11T14:06:18Z`.

| P2 finding | Thread | Comment |
| --- | --- | --- |
| Match root-extra edges when validating approved wheels | PRRT_kwDOT9hvCc6hf6Wv | 3989921446 |
| Reject duplicate approved-artifact filenames | PRRT_kwDOT9hvCc6hf6W5 | 3989921458 |
| Bind keyword arguments for legacy resource reads | PRRT_kwDOT9hvCc6hf6W- | 3989921467 |

Pre-next-review accounting: 114 findings, 111 unresolved inline threads, three
review-level-only findings, and one NOT_APPLICABLE inline finding. No thread
resolution, review dismissal, or merge is part of this correction.

## Approved dependency edges

The exact synthetic `map -> pywebview -> proxy-tools -> helper` chain reproduces
the false rejection. The graph includes helper and carries `selected_extra='map'`
on the normal proxy-tools outgoing edge, but no extra is requested of proxy-tools.
Its activated-extra set is empty. Before correction, an otherwise compliant wheel
declaring `Requires-Dist: helper>=1` fails with “no proxy-tools dependency edge”.

The persisted edge dimensions retain their distinct meanings:

| Field | Meaning |
| --- | --- |
| selected_extra | Selected application/root extra whose path produced the edge |
| requested_dependency_extras | Extras requested of the child (`to_package`) |
| activated_dependency_extra | Optional group of the parent (`from_package`) |

One selection helper now gates both approved-parent presence and dependency-extra
proofs. Root lineage must belong to the graph's selected application extras;
parent optional groups must belong to the approved parent's activated extras.
Normal outgoing edges need no parent extra. Same-name root and parent extras do
not activate each other. Incoming requested child extras remain the source of
approved-package activation, using definitely applicable markers.

The bounded audit of the five requested approved-wheel helpers found one adjacent
gap: incoming-extra collection lacked the selected-root-lineage filter. This is
now checked too. Requires-Dist marker evaluation, version constraints, self
requirements, direct-reference rejection, and child-extra closure remain intact.
No application-wheel proof refactor or persisted field was introduced.

### Actual uv marker-context experiment

`scripts/verify_approved_extra_context.py` constructs local synthetic wheels in a
temporary directory and runs the pinned
`uv 0.12.5 (210d1f678 2026-08-14 x86_64-pc-windows-msvc)` with:

```text
uv lock --offline --no-index --find-links . --python 3.12
```

The experiment does not modify acceptance repositories or execute applications.
Observed uv lock fragments include:

```toml
# pywebview
dependencies = [{ name = "proxy-tools", extra = ["feature"] }]

# proxy-tools
dependencies = [{ name = "helper" }]
[package.optional-dependencies]
feature = [{ name = "optional-helper", marker = "sys_platform == 'win32'" }]
```

Core Metadata originally declared the optional requirement with
`extra == 'feature' and sys_platform == 'win32'`. uv places it in the feature group
and removes the extra predicate from the edge marker. PDB records root lineage
`map` on both outgoing edges, with parent activation `None` on helper and
`feature` on optional-helper. The observed marker has only the platform condition,
so this correction preserves the existing marker-evaluation contract and changes
edge selection. APPLIES can prove presence/extras; false, malformed, or UNPROVABLE
markers cannot. Tests explicitly set optimistic `edge.applicable=True` to prove
the stricter marker check is not bypassed.

## One-to-one approved wheel materialization

A valid generated kit required both `foo==1` and `bar==1`, with two independently
validated wheels. The reproduction then changed foo's record to bar's filename
and SHA, removed foo's file/index entry/reference, retained both lock identities
and suppression pairs, and refreshed the manifest index hash. With bar last, the
old path-keyed identity dictionary silently retained only bar. The self-consistent
tampered kit was **STATIC_VALID before correction**.

`approved_artifacts_by_path` now validates safe kit-relative approved paths and
requires uniqueness under Windows case folding before returning a dictionary.
Static validation reports `APPROVED_ARTIFACT_PATH_UNIQUENESS` and uses that one
validated mapping for both expected identities and wheel-dependency validation.
An invalid set never supplies an overwritten/surviving identity map.

Tests cover exact/case-equivalent duplicate paths, equal SHA values, PEP 440
equivalent version spellings, repeated identity with distinct paths, unsafe
filenames, and valid distinct artifacts. Existing identity and reverse lock
completeness checks remain independent. Application and approved artifacts retain
different materialization directories even when basenames match; installed-path
collision validation remains independent. Canonical sync construction is unchanged.

Generation audit: CLI wheel validation proves filename and METADATA distribution
identity, and `validate_artifact_set` rejects repeated distributions. Thus two
different validated identities cannot ordinarily share a case-equivalent wheel
filename. However, the independently callable manifest builder accepts artifact
records directly. It now invokes the same path invariant before constructing
sync arguments or returning a manifest. No new manifest fields are needed.

## Legacy resource keywords

The exact-head legacy resolver recognizes the function binding but requires two
positional arguments. Running it in memory against the corrected source-mode
fixture reproduced four keyword/mixed-form failures while two positional cases
passed. No production source was reverted for that comparison.

All four already-supported functions (`read_text`, `read_binary`, `open_text`,
`open_binary`) now bind package/resource through the existing `call_argument`.
The 48-case staging matrix covers canonical modules, module aliases, direct
function imports, direct aliases, and positional/mixed/keyword forms. Text forms
retain encoding/errors keywords; binary forms reject them. Positional arguments
still win invalid duplicate bindings.

The existing package-anchor resolver, direct-member restriction, source roots,
containment, and namespace rules remain unchanged. Dynamic/unsafe/nested members,
unrelated functions, and unknown keywords do not produce concrete resource paths.
All four keyword APIs also have promoted-resource configured-secret rejection
tests, including assertions that exceptions do not expose the synthetic value.
Modern importlib.resources and pkgutil semantics are not broadened or changed.

## Read-only acceptance and schemas

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | `f484570d89fb1f9e9170fac915475358dfc1234e` | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python, 77 data members |
| Geo Map Explanation Extractor | `5e7b321d0aeb9ba1d586bfc548c79793d84c6033` | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` | source / SOURCE_COMPATIBLE; existing reviewed kit STATIC_VALID |

Before/after Git working-tree states match. Configuration-name lists are unchanged.
TN's existing kit retains `proxy-tools==0.1.0`; the synthetic helper chain exists
only in disposable PDB fixtures. No wheels, kits, environments, or uv temporary
projects are committed. Analysis schema 1.4 and planning schema 1.3 are unchanged.

## Quality

Focused regression file: **127 passed**. The single complete suite passed:
**1125 passed, 3 skipped in 262.00 seconds**, up from 998 passed, 3 skipped.
`ruff check .` and `git diff --check` passed. The final diff was inspected for
unrelated changes.

The complete suite retains the preceding alias/environment, legacy lock-root,
dynamic-import and pkgutil corrections; MANIFEST/package-surface protections;
exact sync and mode-aware pip contracts; entry-point, short-secret, LOCALAPPDATA,
wheel/dependency, resource/inventory, wheel integrity/security/collision, and
provenance/workflow regressions. Persisted schema versions remain unchanged.
