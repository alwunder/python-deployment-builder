# PR #9: legacy manifest secrets and explicit module resource anchors

Starting head: `2a7556358e4d909dc58a4715ef31d6850f9a9ff1` on
`milestone-6-1-generation-contract`. This records the corrections to the exact-head
review submitted at `2026-09-12T00:14:54Z`:

| Priority | Finding | Thread | Comment |
| --- | --- | --- | --- |
| P1 | Preserve secret scanning for legacy manifests | PRRT_kwDOT9hvCc6hrPQK | 3994357474 |
| P2 | Resolve explicit module anchors for resource files | PRRT_kwDOT9hvCc6hrPQN | 3994357479 |

Accounting remains 120 findings/comments, 117 unresolved inline threads, three
review-level-only findings, and one NOT_APPLICABLE inline finding. The latter is
the automatic flat-package plus loose-module review premise. The three
review-level-only items remain historical #35, approved-wheel PEP 440 semantic
version comparison, and complete locked sync-command validation. No historical
thread is resolved, no review dismissed, and no merge authorized by this work.

## Legacy configured-secret compatibility

Failing regressions were added before production changes. A valid generated
source kit was re-indexed after physically removing `configuration_secret_names`
from its JSON and setting `configuration_presence_names` to `DB_PASSWORD`. An
ordinary indexed source comment, and separately an indexed runtime-helper
comment, contained a synthetic configured value longer than eight characters.
Both received STATIC_VALID before correction: the generic secret patterns did
not independently recognize the fixture. The actual loader returned an empty
default secret list despite retaining the presence name.

Both static and runtime JSON loaders call `DeploymentManifest.model_validate_json`
directly. Tests prove Pydantic's `model_fields_set` excludes the physically absent
field but includes an explicitly serialized empty list. One helper,
`effective_configuration_secret_names`, uses this transient distinction:

| Serialized state | Effective configured-secret names |
| --- | --- |
| secret-name field absent | legacy presence names |
| explicit empty secret-name list | empty; no fallback |
| explicit secret-name subset | exactly that subset |

Static validation computes configured values once and supplies the same values
to indexed source/generated-text scanning and approved/application wheel-member
scanning. Re-indexed, RECORD-consistent approved and first-party wheels are both
rejected when they contain the legacy configured value. The runtime diagnostic
privacy check now uses the same helper; runtime environment isolation itself is
unchanged and continues to remove presence names before restoring harness-owned
LOCALAPPDATA.

Unset and empty legacy values remain benign. Nonempty values shorter than eight
characters fail CONFIGURED_SECRET_SCANABILITY with
SHORT_CONFIGURED_SECRET_UNSCANNABLE; they are not substring-scanned. Regression
assertions verify that values are absent from validation diagnostics, captured
logs, error messages, and manifests. Deliberately contaminated test inputs are
not rewritten or echoed as evidence. Current explicit-empty/subset manifests do
not scan the unrelated DISPLAY_THEME value. Current generation already uses
`model_dump_json(indent=2)` without default exclusion, and its explicit empty
secret-name serialization is now directly tested. Existing old-source-manifest
static validity and release packaging tests remain applicable.

The bounded compatibility audit compared DeploymentManifest with pre-M6.1 commit
`2fc5ec1`. Only `application_artifact` and `configuration_secret_names` were
added. For application_artifact, absent and explicit null intentionally have the
same meaning: accepted for source mode, rejected for package mode. Four focused
tests cover both spellings in both modes. No other defaulted M6.1 manifest field
requires an absence distinction. Reverse approved-artifact completeness and
strict sync-command validation are not bypassed.

## Module resource anchors

The three initial failing resource tests covered positional, anchor=, and
package= string anchors naming `app.config`, physically `src/app/config.py`.
The starting resolver recognized files() but considered package directories only;
the adjacent defaults.json was not promoted.

`scripts/verify_module_anchors.py` runs the actual managed Python 3.12.14
interpreter in disposable fixtures. Observed results:

| Physical anchor | Resulting container |
| --- | --- |
| app/__init__.py | app/ |
| app/config.py | app/ |
| config.py | source root |
| namespace/config.py, without namespace/__init__.py | namespace/ |
| both app/both.py and app/both/__init__.py | app/both/ (regular package wins) |

All four tested runtime forms (positional string, anchor= string, package=
string, and imported module object) read the expected file. package= emits
DeprecationWarning; the other explicit forms do not. These observations agree
with the [Python 3.12 files() documentation](https://docs.python.org/3.12/library/importlib.resources.html#importlib.resources.files).

The script also compares the starting-head anchor function with corrected
analysis against the same disposable source project. Before correction, source
staging omits defaults.json and an isolated Python 3.12.14 read fails with
FileNotFoundError. After correction, the staged source includes the file and the
same read succeeds.

A small shared `analysis/module_resolution.py` now supplies physical locations
to inventory, packaging-directory resolution, and explicit modern resource
anchors. It retains exact, longest-parent and empty package-dir mappings,
configured source roots, and repository containment. Inventory retains regular
initializer promotion without manufacturing namespace initializers. Modern
files() selects a regular package before a same-location module; a module uses
its parent directory. Namespace containers are a fallback, not an extra root
when a concrete package/module is selected. Unsafe concrete anchors cannot be
reinterpreted as namespaces.

Tests cover package/subpackage/module/top-level anchors, namespace parents,
dot/src/lib roots, exact and longest-parent mappings, all established files
bindings and explicit spellings, safe static assignments, missing/dynamic/invalid
anchors, containment, symlink policy, staging, and configured/generic secret
scanning of promoted resources. An installed-only mapping plus an unpackaged
resource still yields DEPLOYMENT_MODE_CONFLICT through the existing planner;
source-compatible layouts stage the resource normally.

The bounded module-object audit found that the resource value engine tracks
literal assignments/returns, not local import-object identities. Its existing
import-binding sets establish the resource API callable, not a general module
object/type environment. Module-object anchors remain explicitly outside this
bounded static model (with negative tests); no generic name/dataflow resolver
was added. Literal and statically assigned string anchors are supported.

Implicit files() is untouched. Legacy functional resource reads and pkgutil
still use their package-only anchor rules; this module-anchor expansion applies
only to modern files(). Python 3.11 remains package-only: package= works, while
anchor= and implicit files() do not. Recognition of Python 3.12 module semantics
does not claim those calls work on 3.11 or redesign target selection.

## Acceptance, schemas, and quality

Read-only starting-head comparisons prove unchanged dependency, entry-point,
configuration, and resource records for all three acceptance repositories. Git
SHAs and working-tree status were preserved.

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | f484570d89fb1f9e9170fac915475358dfc1234e | package / ENTRYPOINT_REQUIRES_PACKAGE_MODE / BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python, 77 data members |
| Geo Map Explanation Extractor | 5e7b321d0aeb9ba1d586bfc548c79793d84c6033 | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | e1e7a1588c37a99c2d02efaf3eef3d04636f12f0 | source / SOURCE_COMPATIBLE; existing kit STATIC_VALID with reviewed proxy-tools==0.1.0 |

SGG's GUI target remains `simple_georef_gui_app.georef_main:main`. Geo retains
LOCALAPPDATA and OPENAI_API_KEY configuration evidence, with no new evidence or
persisted configuration values. No acceptance runtime execution is claimed.

ANALYSIS_SCHEMA_VERSION remains 1.4 and PLANNING_SCHEMA_VERSION remains 1.3.
No persisted field, compatibility flag, or schema migration was added.

The single complete suite passed: **1316 passed, 4 skipped in 316.42 seconds**,
up 67 passes from the 1249-pass baseline. The fourth skip is the new real-symlink
test on this Windows host without symlink-creation permission; independent
mocked-path regressions exercise rejection of unsafe concrete anchors. Ruff and
`git diff --check` pass. Final diff inspection contains only seven production
files, two regression-test files, the synthetic runtime probe, and this report.
No generated wheels, kits, environments, or acceptance artifacts are committed.

The full suite retains PEP 621 omitted/explicit/dynamic field authority, approved
extra-context separation, artifact-path uniqueness, reverse lock completeness,
exact sync arguments, mode-aware pip checks, entry-point extras, short-secret and
LOCALAPPDATA handling, environment aliases, structural lock-root handling,
dynamic imports, modern/legacy/pkgutil resources, MANIFEST/package-data guards,
wheel dependency/security/integrity/collision rules, provenance, rollback, and
deterministic packaging.
