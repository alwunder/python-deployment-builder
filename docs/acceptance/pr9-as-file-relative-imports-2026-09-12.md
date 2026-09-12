# PR #9: as_file resources and relative literal dynamic imports

Starting head: `0d26ebe9b536335d278fabf44477a22fa13a42c1`, branch
`milestone-6-1-generation-contract`. Exact-head review submitted
`2026-09-12T00:57:36Z`:

| Priority | Finding | Thread | Comment |
| --- | --- | --- | --- |
| P2 | Recognize resources passed through as_file | PRRT_kwDOT9hvCc6hrm21 | 3994501628 |
| P2 | Resolve relative literal dynamic imports | PRRT_kwDOT9hvCc6hrm27 | 3994501635 |

Authoritative accounting: 122 findings/comments; 119 unresolved inline threads;
three review-level-only findings (historical #35, approved-wheel PEP 440 semantic
version comparison, and complete locked sync-command validation); one
NOT_APPLICABLE inline finding for the automatic flat-package plus loose-module
premise. No thread closeout, review dismissal, or merge is part of this work.

## Exact reproductions

Two failing regressions preceded production edits. For as_file, the test directly
proves that `_importlib_resource_path_values` already resolves the inner
`files('app') / 'model.dat'`, while `_path_uses` supplies no expression for the
outer wrapper. Assessment therefore produced no resource. The relative import
fixture retained `src/app/examples/plugin.py` as `example_or_snippet`: the old
collector rejected the leading dot without consulting the literal package.

`scripts/verify_resource_wrappers.py` uses disposable, Git-tracked fixtures and
the exact starting-head analysis functions to reproduce generation and execution.
Pinned acquisition/lock preparation are stubbed only for these synthetic kits;
the generated source is executed by managed Python 3.12.14 in isolation.

| Fixture | Starting-head generated kit | Corrected generated kit |
| --- | --- | --- |
| as_file model.dat | STATIC_VALID; runtime FileNotFoundError | STATIC_VALID; runtime reads MODEL |
| .examples.plugin anchored at app | STATIC_VALID; runtime ModuleNotFoundError for app.examples | STATIC_VALID; plugin returns 42 |

No wheel, kit, environment, ZIP, or disposable repository from these experiments
is committed.

## as_file dispatch and runtime evidence

The existing resource import-binding collector now records direct/aliased
as_file imports alongside files and legacy resource functions. Proven module
bindings also recognize `.as_file`. A wrapper dispatch sends its AST argument
directly to the existing Traversable resolver and records read evidence. It does
not first reinterpret the expression as a generic path and does not trace the
context manager's yielded variable. Both an unused yielded path and a path
passed only to another library retain the concrete resource.

Direct probes on Python 3.11.16 and 3.12.14 establish an important signature
limitation: `as_file(traversable=...)` raises TypeError in both interpreters.
The singledispatch wrapper requires a positional argument, despite the displayed
parameter name. PDB therefore accepts the proven one-positional/no-keyword form,
using `call_argument`, and leaves keyword/extra/dynamic/unproven forms unresolved.
No keyword support is inferred solely from signature appearance.

Slash and joinpath expressions, package and module anchors, anchor=/package=
spellings, custom source roots, and exact/longest-parent package-dir mappings all
reuse the preceding resolver. Existing implicit-caller and anchor containment
semantics are untouched.

Directory audit: existing filesystem directories work through pathlib-backed
Traversables in both tested runtimes. Zipped directory materialization fails
with IsADirectoryError on 3.11.16 and succeeds on 3.12.14; zipped files work in
both. This agrees with the documented addition of directory Traversable support
in [Python 3.12 as_file](https://docs.python.org/3.12/library/importlib.resources.html#importlib.resources.as_file).
PDB records the concrete directory and uses its existing directory-resource
coverage rules to retain descendants, without inventing individually accessed
filenames. Tests cover a non-conventional directory name and nested model file.

Release tests reject configured and obvious secrets in referenced text, without
exposing configured values in errors. Git-backed tests reject dirty and
untracked referenced model files. The ordinary shared secret-file, containment,
role, and provenance policies remain in force.

## Relative literal dynamic imports

One pure helper consumes name at position zero/name= and, for a relative name,
package at position one/package=. Both use the established positional-wins
`call_argument` policy. Literal relative names are resolved by
`importlib.util.resolve_name`; this function resolves strings without importing
target code. Package anchors and resulting absolute module identities must have
valid dotted identifier components. Above-root resolution errors fail closed.

Tests prove `.plugin` + app, `.examples.plugin` + app, `..plugin` + app.sub,
positional/keyword packages, name=, module/direct-function aliases, duplicates,
and absolute names with ignored package arguments. Missing/dynamic package
anchors, dynamic/f-string names, and malformed results remain unresolved.
The behavior follows [Python's relative import resolution contract](https://docs.python.org/3.12/library/importlib.html#importlib.util.resolve_name).

Resolved identities feed the existing `_module_files` / `module_locations`
pipeline. Tests retain examples/docs/tests targets, regular initializers,
namespace ancestors, custom lib roots, exact and longest-parent mappings, and
source staging. Installed-only mappings continue through the existing package
mode constraints; no planner special case was added.

## Bounded adjacent audit

The Traversable terminal operations already supported by resources.py continue
to dispatch through the existing path-use machinery. No additional wrapper gap
was established within the requested scope, and no new resource API families
were added beyond as_file.

The builtin import audit found one adjacent false-evidence case: the old
collector treated an absolute-looking string passed to `__import__` as absolute
even when an explicit level changed its meaning. The bounded correction rejects
nonzero or unresolved level values, while retaining omitted/literal-zero level
absolute calls. Builtin globals/locals/fromlist/relative-context emulation was
not added, and import_module's package argument is never applied to the builtin.

`package=__package__` remains outside the literal dynamic-import model. Existing
source-package contexts can contain multiple identities for overlapping roots;
physical package-dir relocation and script-versus-package execution add further
ambiguity. They do not provide a generally unique runtime __package__ value.
No new dataflow/context engine was introduced; a regression records this limit.

## Acceptance, compatibility, and quality

Read-only comparisons with starting-head analysis confirm identical dependency,
entry-point, configuration, and resource evidence in all acceptance repositories.
Their Git SHAs and working-tree status remain unchanged.

| Repository | SHA | Contract |
| --- | --- | --- |
| SimpleGeorefGUI | f484570d89fb1f9e9170fac915475358dfc1234e | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python and 77 data members |
| Geo Map Explanation Extractor | 5e7b321d0aeb9ba1d586bfc548c79793d84c6033 | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | e1e7a1588c37a99c2d02efaf3eef3d04636f12f0 | source / SOURCE_COMPATIBLE; existing kit STATIC_VALID with reviewed proxy-tools==0.1.0 |

SGG's GUI target remains `simple_georef_gui_app.georef_main:main`. No new resource
or configuration evidence was discovered in these repositories by this change.
No new acceptance-repository runtime execution is claimed.

ANALYSIS_SCHEMA_VERSION remains 1.4; PLANNING_SCHEMA_VERSION remains 1.3.
No persisted model or compatibility flag changes were required.

The single complete suite passed: **1401 passed, 4 skipped in 305.91 seconds**,
up 85 passes from the 1316-pass baseline, with no additional skips. Ruff and
`git diff --check` pass, including the staged diff. Inspection confirms only the
two production analysis files, focused regression file, disposable verification
script, and this report changed.

The full suite preserves legacy-manifest absent-versus-empty secret handling,
source/generated/wheel scanning parity, module resource anchors, PEP 621 field
authority, approved-extra separation, artifact-path uniqueness, exact sync and
reverse lock completeness, mode-aware pip checks, entry-point extras, short
secrets and LOCALAPPDATA ordering, wheel dependency/security policies,
MANIFEST/package-data guards, provenance, rollback, and deterministic packaging.
