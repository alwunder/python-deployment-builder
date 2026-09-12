# PR #9: named automatic layouts and positional legacy text arguments

Starting head: `94b3fd52e3cfa2a6c4f5ebbb287b6255e291b43a`.
Branch: `milestone-6-1-generation-contract`. Do not merge.

## Review accounting

Exact-head review submitted `2026-09-12T01:50:25Z`:

| Finding | Thread | Comment |
| --- | --- | --- |
| P2: Honor named package-dir mappings during auto-discovery | `PRRT_kwDOT9hvCc6hsBoB` | `3994664774` |
| P2: Accept positional encoding arguments in legacy resource reads | `PRRT_kwDOT9hvCc6hsBoH` | `3994664779` |

Authoritative totals: 124 findings/comments, 121 unresolved inline threads,
three review-level-only findings (historical #35, approved-wheel PEP 440
comparison, complete locked sync-command validation), and one inline
`NOT_APPLICABLE / REVIEW PREMISE INCORRECT` finding for automatic flat package
plus loose module behavior. GitHub independently returned 121 threads and zero
resolved threads during this correction. No threads or reviews were closed or
dismissed.

## Pinned setuptools reproduction and discovery correction

`scripts/verify_named_layout_text_signatures.py` creates disposable projects,
builds wheels with uv 0.12.5 and isolated setuptools **79.0.1**, and compares the
actual installed Python members to PDB's assessed surface. It does not execute
builds in production analysis or touch acceptance repositories.

Before the correction, `app -> lib` yielded PDB packages `['lib']`, although
setuptools installed exactly `app/__init__.py`, `app/main.py`, and
`app/helpers.py`. Applying the starting-head metadata inspector to the same
correct wheel reproduced the rejection:

```text
Application wheel is missing authoritative first-party Python source:
lib/__init__.py, lib/helpers.py, lib/main.py
```

After correction that actual wheel validates. Seven initial tests failed before
the production edits: three metadata-source variants and four positional text
read variants.

The complete wheel-build matrix covered each of pyproject, setup.cfg, and
literal setup.py, including **build-system-only legacy projects**:

| Layout | Observed setuptools result / corrected PDB result |
| --- | --- |
| `app -> lib` | Installed root `app`, not `lib`; physical root initializer belongs to `app` |
| Regular and namespace descendants | `app.sub`, `app.ns`; no fabricated initializer |
| Namespace mapped root | `app/main.py` without `app/__init__.py` |
| `app.plugins -> vendor/plugins` | `app.plugins` and namespace child packages |
| Independent `app` and `other` roots | Both installed identities retained |
| Parent `app` plus specific `app.special` | `app.normal` from parent; `app.special` and child members from specific mapping; shadow parent's `wrong.py` absent |
| Missing mapped directory | Setuptools build fails; PDB marks surface unresolved without fallback |
| Global `"" -> lib` | Src-layout packages, namespace packages, and loose modules all discovered |

Named mappings now precede generic automatic layout selection only when no
explicit package/module selection or finder is configured. The mapped root is
itself a package identity; existing namespace discovery supplies descendant
names relative to that root. Finder exclusions apply before prefixing, matching
setuptools. The shared `module_locations()` provides safe installed-name
locations, retaining exact/longest-parent precedence for downstream member
resolution. External roots prevent partial automatic authority; missing or
unsafe mapped roots never cause generic rediscovery under a physical name.

Explicit and wildcard package-data tests require both `app/data/a.json` and
`app/data/b.json`; exclusion removes only the declared member. Correct wheels
pass, missing `app/helpers.py` fails, and missing selected package-data fails.
Local import location agrees with the same installed identity. A physically
source-compatible named mapping remains `source / SOURCE_COMPATIBLE`; a renamed
entry-point layout retains `package / ENTRYPOINT_REQUIRES_PACKAGE_MODE`.

Bounded layout audit found one additional same-class defect: the old automatic
logic treated a global custom root `"" -> lib` as flat-layout, losing `tests`
namespace/package members and `helper.py`. The pinned build reproduced this in
all three metadata forms. The correction distinguishes src-layout semantics
from the literal directory spelling `src`, preserving flat-layout's existing
package-over-loose-module rule. Explicit empty selections still disable auto
discovery; named mappings take precedence when combined with a global mapping.
No discovery architecture or persisted contract was redesigned.

The reference implementation is the pinned
[setuptools discovery source](https://github.com/pypa/setuptools/blob/v79.0.1/setuptools/discovery.py).
The report's concrete member results come from the disposable builds, not an
assumption based on newer setuptools behavior.

## Exact Python resource signatures and correction

Direct interpreter execution used **Python 3.11.16** and **Python 3.12.14**.
Both produced identical bounded call behavior:

| API | Accepted positional arguments | Rejected |
| --- | --- | --- |
| `read_text`, `open_text` | package, resource, optional encoding, optional errors | Fifth positional, duplicate encoding, unrelated keyword |
| `read_binary`, `open_binary` | package, resource | Third/fourth positional, encoding/errors keywords |

Two-, three-, and four-positional text calls returned the fixture content.
Mixed positional package plus keyword resource/encoding/errors also worked.
The probe prints exact signatures and asserts expected successes/TypeErrors.
Keyword-before-bare-positional test cases were not fabricated.

Pre-fix analysis rejected `len(args) > 2`, so the actual text resource was not
recorded or staged. Text helpers now accept up to four positional arguments;
binary helpers retain their two-argument limit. `call_argument()` still binds
only package/resource. Optional encoding/error expressions need not be literal,
because they do not change resource identity. Duplicate optional text bindings
are unresolved; the previously accepted positional-wins behavior for invalid
duplicate package/resource bindings remains unchanged.

Direct, module-qualified, module-alias, and directly imported alias forms all
retain resource evidence. Unknown keywords, unrelated functions, dynamic
package/resource values, traversal, and nested legacy members remain unresolved.
Successful resolution uses the existing package-anchor and role-aware staging
path. Release generation rejects a synthetic configured value in the newly
recognized text resource without including its value in the diagnostic.

The bounded audit of the four legacy resource APIs found no additional
signature discrepancy beyond optional positional text arguments and their
duplicate-binding guard. Modern files(), as_file(), and pkgutil semantics were
not changed.

## Read-only acceptance checks

Assessment comparisons against the starting-head metadata/resource recognizers
found identical packaging metadata, dependencies, entry points, configuration
evidence, and resources. Before/after repository statuses and SHAs matched.

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | `f484570d89fb1f9e9170fac915475358dfc1234e` | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python, 77 data members |
| Geo Map Explanation Extractor | `5e7b321d0aeb9ba1d586bfc548c79793d84c6033` | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` | source / SOURCE_COMPATIBLE; reviewed proxy-tools 0.1.0 |

SGG **does** have `simple_georef_gui_app -> code`, but explicitly selects
`packages = ['simple_georef_gui_app']`; it does not enter automatic discovery.
Its GUI target remains `simple_georef_gui_app.georef_main:main`. The 13/77
surface was recomputed, not assumed.

TN's existing `pdb-m61-regression-20260901/tn-kit` independently remains
`STATIC_VALID` with the reviewed artifact. No acceptance wheels, environments,
source files, locks, or kits were modified.

## Quality and compatibility

Analysis schema remains **1.4**; planning schema remains **1.3**. No persisted
fields, manifest defaults, or migrations were introduced.

Focused new regressions: **123 passed**. The single complete suite finished
with **1524 passed, 4 skipped** in 322.21 seconds, versus the prior
1401-pass/four-skip baseline. `ruff check .` and `git diff --check` passed.
The final diff contains only the two production corrections, their focused
tests, the disposable verification script, and this text evidence report.

Prior regression coverage includes as_file, relative dynamic imports, legacy
manifest configured-secret compatibility, module anchors, omitted PEP 621
authority, approved artifact paths/extra contexts/lock identity, exact sync,
mode-aware pip check, entry-point extras, short secrets, LOCALAPPDATA ordering,
MANIFEST/include-package-data guards, wheel security/dependencies/integrity,
provenance, rollback, and deterministic packaging.

Only the PR Quality pass count may be updated after all gates pass. One focused
commit and one exact-pushed-head `@codex review` request are authorized; no merge
or historical thread resolution is authorized.
