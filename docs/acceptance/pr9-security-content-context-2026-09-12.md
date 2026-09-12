# PR #9: operational write heuristic context

Remote/local HEAD remains `4888ee28710d20dc8e45886ad4d928f0f556aa66`.
The two prior review corrections remain uncommitted and preserved.
This additional correction is **PRE_EXISTING_ACCEPTANCE_POLICY_FALSE_POSITIVE**,
not another Codex review finding. Accounting remains 127 findings/comments,
124 unresolved inline threads, three review-level-only findings and one
NOT_APPLICABLE inline finding.

## Reproduction and correction

Five failing regressions preceded the policy edit. A valid wheel whose METADATA
contained descriptive text about making a data-only copy without copying Program
Files security descriptors was rejected by the original shared scanner.

The actual accepted SGG wheel retains SHA-256
`e479d668a59e879bbc42ee3d32ffcc89ce3bf40dc65d6c52d703be44703ede03`.
Its `simple_georef_gui-1.3.dist-info/METADATA` line 352 contains embedded README
documentation about copying a read-only ArcGIS Pro environment without copying
Program Files security descriptors. METADATA is descriptive, not executed write
code. Executing the security-policy module obtained with `git show` from the
starting SHA against those exact bytes returned only `program_files_write`.
The corrected path-aware scanner returns no findings for those same bytes.

`program_files_write_applicable()` exempts only known descriptive `.md`, `.rst`,
`.txt` paths and standard direct `.dist-info` metadata names from this heuristic.
Python, BAT and CMD are PDB's generated executable forms and remain checked.
HTML application resources, `.pth` startup files, JavaScript and unknown text
paths remain conservatively checked rather than being exempted by a narrow
executable-extension allowlist. Pathless compatibility calls retain the original
conservative behavior. No distribution, filename or sentence special case exists.

Every production caller now supplies path context: `generation/structural.py`
(rendered/generated and staged source), `generation/artifacts.py` (application
and approved wheel members), and `validation/static.py` (independent static kit
scanning). An AST regression verifies all production calls carry `path`.

The bounded adjacent audit leaves every other finding untouched. Secrets and
developer paths are meaningful leaks in documentation. No direct acceptance
evidence justifies changing forbidden-shell or permanent-PATH policy, so both
remain active on documentation/METADATA. UTF-8 classification and secret-file
checks are unchanged. Multiline Python writes and realistic BAT/CMD copies into
Program Files still fail.

## New independent acceptance blocker: historical stop gate

This stop-point was subsequently resolved under explicit user direction; see
[minor-marker proof and completed acceptance](pr9-minor-marker-acceptance-2026-09-12.md).
The evidence below records the earlier run, not the current acceptance state.

SGG source is still `f484570d89fb1f9e9170fac915475358dfc1234e`, with the
unchanged 13 Python / 77 package-data surface and package-mode entry point.
The accepted wheel passes security scanning and the 90-member authority check.
Full generation now proceeds to strict locked dependency validation and fails:

```text
Application wheel Requires-Dist presence cannot be proven from a definitely
applicable direct locked dependency edge for numpy:
python_full_version < '3.11';
python_full_version == '3.11.*';
python_full_version >= '3.12'.
```

This is distinct from the corrected documentation policy false positive. Per the
explicit instruction to stop on another acceptance blocker, no dependency-proof
changes, further acceptance attempts, full-suite run, runtime validation or ZIP
packaging were undertaken after this failure. The historical deterministic SGG
ZIP hash has not been represented as regenerated evidence.

## Verification and state

- New policy tests: **52 passed** after correcting a test-call keyword typo.
- The prior 86 review-correction cases also passed in the focused combined run;
  its four policy-test failures were the same subsequently corrected test typo.
- Last complete suite remains the preceding local baseline: **1801 passed,
  4 skipped**. A new complete suite was not run because the acceptance stop gate
  was reached.
- Analysis/planning schemas remain **1.4 / 1.3**; no new persisted policy field.
- Geo/TN acceptance results from the preceding turn remain recorded separately;
  acceptance was not repeated after the SGG stop gate.
- No commit, push, PR Quality/evidence edit, review request, thread resolution,
  review dismissal or merge.

PR #9 STILL REQUIRES CORRECTION
