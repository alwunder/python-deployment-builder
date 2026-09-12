# PR #9: application surface and assigned Traversables

Starting head: `4888ee28710d20dc8e45886ad4d928f0f556aa66` on
`milestone-6-1-generation-contract`. Changes remain local pending the acceptance
blocker below. No merge, review dismissal, thread resolution, push, PR edit, or
fresh review request was performed.

## Findings and reproduction

The exact-head review submitted at `2026-09-12T18:56:17Z` reported:

- P1 **Reject undeclared executable members in application wheels**:
  `PRRT_kwDOT9hvCc6hypCG`, comment `3997215864`.
- P2 **Follow assigned Traversables when resolving resource reads**:
  `PRRT_kwDOT9hvCc6hypCJ`, comment `3997215868`.

Authoritative accounting remains 127 findings/comments, 124 unresolved inline
threads, three review-level-only findings, and one NOT_APPLICABLE inline finding.
GitHub confirmed 124 threads and zero resolved threads during this turn.

Five regressions were added and run before production changes. All five failed:

- A correct mapped application wheel plus `requests/__init__.py` was accepted.
- A root `application-hook.pth` was accepted.
- A `.data/purelib/application-hook.pth` relocated to the installed root was accepted.
- `asset = files('app') / 'model.dat'; as_file(asset)` lost the resource.
- The same assignment followed by `asset.read_bytes()` lost the resource.

The wheel fixtures had valid metadata, tags, entry points and recomputed RECORDs.
The source fixture had no independent package-data/resource-directory promotion.
The pre-fix resource assessment was empty; the wheel checks only required the
modeled files to be a subset of installed files.

## Source-derived application authority

`ApplicationArtifact.authoritative_members` is required and nonempty. Generation
stores the sorted union of source-resolved installed Python and package-data
members. It never records wheel inventory as authority. The entry-point module
must also belong to the source-derived Python surface, not merely occur in the
wheel or be inferred from packaged data.

Generation and independently callable static validation share a relocated
installed-member validator. It requires every authoritative member, rejects
unmodeled `.py` members case-insensitively by suffix, and uses the established
Windows path/collision checks. Required-member spelling remains exact, consistent
with prior completeness checks. Metadata is excluded through the existing
installed application-surface resolver. `.data/purelib` relocation occurs before
enforcement. Extra benign non-executable data is not blanket-rejected.

Root `.pth` files are forbidden regardless of content. Nested inert `.pth` data
is not a startup destination. The bounded startup audit inspected managed
CPython 3.12.14 `site.py` and executed isolated disposable probes: both
`sitecustomize` and `usercustomize` can be imported as modules **or packages**;
`.pth` processing also executed a harmless probe. Consequently their top-level
`.py` and package `__init__.py` destinations are forbidden even when declared.
No broader startup mechanism was added.

The static check is `APPLICATION_WHEEL_AUTHORITATIVE_SURFACE`. Re-indexed tests
replace the wheel, recompute RECORD, artifact SHA, deployment fingerprint,
generation ID and generated-file hashes. Foreign Python, startup files, missing
Python and missing package data still fail while metadata/index checks pass.
Legitimate second packages and py-modules pass; existing collision fixtures now
declare their intentionally colliding Python code in their source surfaces.

The authoritative list participates in the ordinary deployment fingerprint. A
one-member change changes that fingerprint. No sidecar or source reassessment is
needed during static validation. This remains a manifest contract, not a new
cryptographic attestation of source-to-wheel provenance.

### Serialized contract decision

Analysis schema stays **1.4**, planning schema stays **1.3**, and the deployment
envelope stays **1.0**. Package mode is an unreleased M6.1 contract; its artifact
shape is strengthened now without an insecure compatibility default. Missing or
empty authoritative lists fail model validation. Old source-mode manifests with
no application artifact retain their existing compatibility behavior. Current
package manifest bytes and fingerprints change, so historical SGG ZIP hashes
cannot be reused as evidence for a regenerated kit.

## Assigned Traversables

`_importlib_resource_path_values()` follows the existing `_bindings()` assignment
map directly, with separate cycle keys for assignments and local returns. The
same recursion handles names, stable qualified attribute keys, slash/joinpath
bases, multi-hop aliases and direct no-argument local return expressions.
Assignment and return cycles terminate unresolved. Parameter substitution,
arbitrary object calls and control-flow-sensitive mutation are not modeled.
The existing deterministic `_bindings()` assumptions are unchanged.

The bounded adjacent audit found attribute keys and local return mappings already
available to ordinary path analysis. Traversable support reuses those mappings;
it does not introduce a call graph or context-manager yielded-variable tracking.

Package, module, implicit, positional, `anchor=` and `package=` anchors retain
their existing semantics. Tests cover custom/global roots, exact/longest-parent
mappings, namespace parents, directory descendants, dynamic/cyclic inputs and
containment. Assigned `as_file`, `read_bytes` and `read_text` all promote resources.
Generated source-kit tests perform isolated interpreter reads successfully.
Configured-secret content, dirty files and untracked files still block release;
the secret value does not occur in exception diagnostics.

## Acceptance results and blocker

All three acceptance repositories retained their exact SHAs and Git status.
Comparing current analysis with the starting-head resource resolver showed no
dependency, entry-point, configuration, packaging or resource drift.

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | `f484570d89fb1f9e9170fac915475358dfc1234e` | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python + 77 package-data members; GUI target unchanged |
| Geo Map Explanation Extractor | `5e7b321d0aeb9ba1d586bfc548c79793d84c6033` | source / SOURCE_COMPATIBLE; no application artifact |
| TN Coordinate Converter | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` | source / SOURCE_COMPATIBLE; existing kit STATIC_VALID; proxy-tools 0.1.0 retained |

The accepted SGG application wheel is:

`simple_georef_gui-1.3-py3-none-any.whl`

SHA-256: `e479d668a59e879bbc42ee3d32ffcc89ce3bf40dc65d6c52d703be44703ede03`.

Its independent **new surface check passes all 90 source-derived members** with
no undeclared Python or startup destinations. However, full regeneration stops
before that check at the existing security policy:

`Wheel content violates deployment security policy: simple_georef_gui-1.3.dist-info/METADATA`

The rule is `program_files_write`. METADATA line 352 is descriptive documentation
about copying an ArcGIS Pro environment without copying Program Files security
descriptors. The existing whole-text token rule treats the combination of
`Program Files` and `copy ` as a violation; this is not evidence of an actual
write to Program Files. The starting-head `validate_application_wheel()` function
was executed against the same source/plan/wheel and rejects the same METADATA.
Thus the blocker predates these two corrections. Every saved SGG application
wheel found in the acceptance locations has the same SHA.

No acceptance source or wheel was edited and no security exemption was added.
The newly created external acceptance output directory has no generated kit.
SGG runtime revalidation, final automated state and twice-packaged deterministic
ZIP evidence therefore remain **not completed**. The old PR hash is historical,
not refreshed evidence. Resolving this requires direction for the pre-existing
metadata policy false positive or an accepted replacement artifact.

## Quality and historical handoff

The acceptance blockers recorded above were subsequently resolved under explicit
user direction. See [completed acceptance](pr9-minor-marker-acceptance-2026-09-12.md)
for the refreshed SGG runtime/ZIP evidence and final combined quality gate.

- New focused regression file: **86 passed**.
- Resource-focused run before the last startup/isolated-read additions:
  **407 passed, 1 skipped**.
- One complete suite: **1801 passed, 4 skipped** in 341.25 seconds (baseline
  1715 passed, 4 skipped; 86 additional passing cases).
- Ruff: passed.
- `git diff --check`: passed; final inspection found no unrelated changes.
- No generated wheel, kit, environment or ZIP is part of the local diff.
- Commit/push, PR Quality/evidence changes and the single fresh review request are
  withheld because SGG acceptance has not passed.

PR #9 STILL REQUIRES CORRECTION
