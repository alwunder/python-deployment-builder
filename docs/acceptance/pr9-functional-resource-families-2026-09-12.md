# PR #9: Python 3.13+ functional resource paths

Starting head: `0ce99790f26e256b1cc4ab1c3879d5db70b8cb1d`.
Branch: `milestone-6-1-generation-contract`. Do not merge.

## Fresh review and accounting

Exact-head review submitted `2026-09-12T03:15:07Z` raised P2:
**Support multi-part resource names on Python 3.13+**.
Thread: `PRRT_kwDOT9hvCc6hsp4y`; review comment: `3994907452`.
The comment and its commit identity were independently checked through GitHub.

Authoritative totals: **125 findings/comments**, **122 unresolved inline
threads**, **three review-level-only findings**, and **one NOT_APPLICABLE inline
finding**. The three review-level-only findings remain historical #35,
approved-wheel PEP 440 comparison, and complete locked sync-command validation.
The NOT_APPLICABLE finding remains automatic flat package plus loose module
behavior. GitHub returned 122 threads, zero resolved. No review dismissal,
historical thread resolution, or merge is authorized by this correction.

## Direct interpreter evidence

`scripts/verify_functional_resource_families.py` executes disposable fixtures
under managed CPython **3.11.16**, **3.12.14**, **3.13.15**, and **3.14.7**.
The latter two were acquired using the existing pinned uv **0.12.5** workflow.
No acceptance repository was used as a test fixture.

| Call behavior | 3.11.16 | 3.12.14 | 3.13.15 | 3.14.7 |
| --- | --- | --- | --- | --- |
| Binary `(package, filename)` | Read succeeds | Read succeeds | Read succeeds | Read succeeds |
| Binary `(anchor, directory, filename)` | TypeError | TypeError | Read succeeds | Read succeeds |
| Binary one slash-containing path name | ValueError: direct filename required | Same | Read succeeds | Read succeeds |
| Text two positional arguments | Read succeeds | Read succeeds | Read succeeds | Read succeeds |
| Text positional encoding / encoding plus errors | Read succeeds | Read succeeds | TypeError: encoding argument required with multiple path names | Same |
| Text multipart names plus `encoding=` | Duplicate encoding TypeError | Same | Read succeeds | Read succeeds |
| Text deeper multipart path plus `encoding=` | Duplicate encoding TypeError | Same | Read succeeds | Read succeeds |
| Text multipart names without `encoding=` | Legacy interpretation; fixture attempts to open a directory | Same | TypeError: encoding argument required | Same |
| `package=` / `resource=` | Read succeeds | Read succeeds | Unexpected keyword TypeError | Same |
| `anchor=` with no path names | Unexpected keyword TypeError | Same | Directory read fails | Same |
| Invented `path_names=` keyword | Unsupported | Unsupported | Unsupported | Unsupported |
| Module / top-level module / namespace-parent module anchor | Not a package TypeError | Read succeeds | Read succeeds | Read succeeds |

Both read/open variants of binary and text functions were executed. On Windows,
attempting to open a directory in these fixtures raises PermissionError. This
is not evidence for a recursive directory resource read.

An important bounded audit result is that **3.12's older functional wrappers
already inherit module-anchor behavior from files()**. The resource resolver
therefore uses the existing shared module/package resolver for both families,
not a new module-name-to-path implementation. Regular packages continue to win
over same-named module files; no initializer is invented for namespace parents.

The [Python 3.13 functional API documentation](https://docs.python.org/3.13/library/importlib.resources.html#functional-api)
describes the signature transition. All patch-version behavior above was also
verified by direct execution rather than inferred from documentation.

## Private call classifier and target-independent policy

`_FunctionalResourceCall` is a private frozen dataclass containing only AST
anchor/path expressions and a `legacy_direct`, `multipath`, or `common` family.
It is not a persisted model, and no runtime target is threaded into assessment.

The bounded classifier recognizes shapes valid for at least one supported
family. For text, multiple positional path names require keyword encoding on
3.13/3.14; that same keyword conflicts with positional encoding on 3.11/3.12.
Consequently the valid families do not assign different file identities to the
same supported call shape. Without keyword encoding, old three-/four-positional
text forms retain the direct-member interpretation. With keyword encoding,
the new multipart interpretation is selected where valid.

This is resource evidence, **not a promise that every recognized call executes
on every Python minor**. Existing planning and runtime validation remain
responsible for deployment behavior. Python 3.15 or later signature changes
are outside this four-minor policy audit.

Old `package=`/`resource=` forms remain legacy-only. New `anchor=` has no useful
file-read form with keyword path names: varargs are positional, and supplying
only the anchor selects its directory. Such calls stay unresolved. Starred
argument expansion, unknown keywords, and duplicate keywords are unresolved.
The existing positional-wins compatibility behavior for duplicate legacy
package/resource bindings remains unchanged; it does not manufacture two
anchors or two resource identities. Conflicting optional text bindings are
accepted only if a valid new-family interpretation exists.

Each required path expression must resolve to exactly one string using the
existing bounded assignment/value engine. Components are flattened and joined
with POSIX resource semantics. Forward-slash subpaths are supported where the
new family applies. Absolute names, backslashes, drive/colon tricks, traversal,
empty/dot segments, and unresolved components are rejected. Old-only keyword
and positional-encoding forms retain the direct-member restriction. Functional
file reads do not promote directories, preventing a missing-encoding text call
from accidentally rescuing all descendants.

## Exact pre/post deployment reproduction

The disposable Git-tracked source fixture contains `src/app/models/weights.bin`
and `read_binary('app', 'models', 'weights.bin')`, without package-data rescue.
Its Python requirement selects 3.13. Preparation/acquisition are controlled
offline fixture hooks; independently callable static validation runs normally.
The staged application is executed using managed Python 3.13.15 with `-E -s -B`.

| Resolver | Resource included | Static validation | Isolated staged execution |
| --- | --- | --- | --- |
| Starting-head function | No | STATIC_VALID | FileNotFoundError for omitted weights.bin |
| Corrected function | Yes | STATIC_VALID | Reads RESOURCE successfully |

Before implementation, four focused tests failed for read_binary, open_binary,
read_text, and open_text. They demonstrated absent concrete resource evidence.
Post-fix tests prove RUNTIME_RESOURCE promotion and source staging. Additional
text fixtures prove `templates/defaults.txt` staging with explicit functional
read evidence, rather than depending solely on conventional directory names.

## Safety, package constraints, and bounded audit

Focused tests cover all four functions, all proven alias forms, one-slash and
multipart paths, one/three/eight directory levels, static assignments, dynamic
encoding/errors, unresolved dynamic components, old keyword calls, conflicting
arguments, package/subpackage/module/top-level anchors, custom roots, exact and
parent mappings, namespace parents, package-over-module precedence, and resolved
repository escapes.

Release tests reject a configured synthetic value in a nested text resource
without leaking that value in the exception. Dirty and untracked referenced
resources also reject release generation. Existing scanners, provenance,
binary-content policy, and staging machinery are reused without modification.

A mapped installed-only application with an unbacked nested resource yields
DEPLOYMENT_MODE_CONFLICT. Explicit package-data makes that resource packaged
and preserves ENTRYPOINT_REQUIRES_PACKAGE_MODE. Analysis does not add arbitrary
resources to package_data or weaken first-party wheel completeness.

The bounded audit covered only read_binary, open_binary, read_text, and open_text.
It closed the same-transition text-signature and module-anchor cases. It did
not add path(), is_resource(), contents(), new library families, general Python
binding/dataflow, or target-conditioned persisted resource fields.

## Read-only acceptance

All repository SHAs and before/after statuses matched. Comparisons against the
starting-head recognizer found identical packaging metadata, dependencies,
entry points, configuration evidence, and resource evidence. No proven calls
to these four functional APIs were found in the assessed packaged Python
surfaces of the three acceptance repositories.

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | `f484570d89fb1f9e9170fac915475358dfc1234e` | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python / 77 data members |
| Geo Map Explanation Extractor | `5e7b321d0aeb9ba1d586bfc548c79793d84c6033` | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` | source / SOURCE_COMPATIBLE; reviewed proxy-tools 0.1.0 |

SGG's GUI target remains `simple_georef_gui_app.georef_main:main`. TN's existing
`pdb-m61-regression-20260901/tn-kit` remains independently STATIC_VALID. No
acceptance sources, wheels, kits, locks, or environments were changed.

## Quality and preservation

New focused tests: **191 passed**. Broader targeted resource/layout suite:
**760 passed, 1 skipped**. The single complete suite finished with
**1715 passed, 4 skipped** in 330.85 seconds, versus the prior 1524-pass/four-skip
baseline. `ruff check .` and `git diff --check` passed. A separate release probe
confirmed the configured-secret rejection is specifically NO_SECRET_VALUES,
with no diagnostic value leakage and no published kit.

Schemas remain analysis **1.4**, planning **1.3**. Production changes are limited
to analysis/resources.py. Named-layout discovery, old text signatures, modern
files/as_file/module anchors, relative dynamic imports, legacy-manifest secret
compatibility, PEP 621 authority, approved-artifact paths/extra contexts/lock
identity, exact sync, mode-aware pip check, entry-point extras, short secrets,
LOCALAPPDATA, MANIFEST protections, wheel policy/dependency/security, provenance,
rollback, and deterministic packaging retain their regression coverage.

Only after every gate passes: one correction commit, matching pushed head,
Quality-only PR count update, and exactly one `@codex review` request. No merge,
review dismissal, or historical inline-thread resolution.
