# PR #9: proven bindings, keyword reads, and legacy lock roots

Starting head: `a94c1b69f7934a7a0f89f725c17f135ee3296cea`.
Review submitted: `2026-09-11T12:28:22Z`.
Accounting before the next review: 111 findings, 108 unresolved inline threads,
three review-level-only findings, and one NOT_APPLICABLE inline finding.
This correction does not resolve threads, dismiss reviews, or authorize merge.

## Fresh findings and reproduction

| Finding | Comment | Correction |
| --- | --- | --- |
| P1: Track aliased environment APIs when collecting secrets | 3989107557 | Precompute explicit stdlib import bindings before visiting runtime reads. |
| P2: Preserve the root identity for legacy source manifests | 3989107568 | Cross-check structural lock identity; block actual rootless legacy projects before generation. |
| P2: Read the dynamic-import name keyword | 3989107573 | Use the existing `call_argument` for `name`. |
| P2: Resolve keyword-form pkgutil resource reads | 3989107579 | Use the same helper for `package` and `resource`. |

The initial regression run, before production edits, produced **55 failures and
22 passes**. Aliased `os.getenv`, imported/aliased `getenv`, and imported/aliased
`environ.get` calls were present in the AST but retained alias spellings and
produced no configuration requirements. Thus their names did not reach manifest
secret lists or configured-value scanning. Keyword dynamic imports did not stage
their excluded-scope targets; keyword pkgutil reads did not stage their resources.
The legacy source kit was generated but failed static lock identity validation.

## Bounded AST contract

Explicit absolute imports provide file-level binding evidence, independently of
the textual order of imports and function declarations. Wildcard imports,
relative imports, and unrelated user functions are not proof of stdlib origin.
This is not runtime import execution or a general lexical name-resolution engine.

The environment matrix covers canonical and aliased os modules, directly imported
and aliased getenv functions, and directly imported/aliased environ objects,
including get/subscript reads, positional/keyword keys, defaults, dynamic keys,
and non-identifier environment names. Aliased secrets reach assessment, planning,
manifest name lists, configured-value lookup, staged resource scans, and
application/approved-wheel scans. Synthetic-value assertions cover serialization
and exception/log output; short configured secrets retain their fail-closed rule.

Dynamic imports use the existing proven importlib/builtin bindings, literal
absolute dotted-name policy, and local-module resolver. Keyword names follow the
same source-root, initializer, containment, staging, and deployment-mode paths as
positional names. Dynamic, f-string, relative, and malformed names remain unresolved.

Pkgutil accepts positional, mixed, and fully keyword-bound arguments for the
existing proven aliases. Positional values win duplicate bindings, as in the
shared helper. Extra arguments, unrelated keywords, dynamic values, unsafe paths,
and namespace-only packages remain unresolved. A keyword argument followed by a
bare positional resource is invalid Python syntax, not another supported form.
Nested safe resources and declared package-data behavior retain existing rules.

The one bounded binding audit also corrected aliases of already-supported runtime
APIs in os, subprocess, ctypes, shutil, and webbrowser; resource directory reads
through os.listdir/scandir aliases; and relative imports incorrectly supplying
stdlib resource binding evidence. Focused tests accompany these changes. No new
API family, general argument binder, or generic name-resolution engine was added.

## Actual uv 0.12.5 evidence and identity decision

The explicit developer script `scripts/verify_legacy_lock_root.py` was run against
`uv 0.12.5 (210d1f678 2026-08-14 x86_64-pc-windows-msvc)` with `uv lock --python 3.12`.
It creates disposable fixtures outside the repository. Applications are not run.

| Fixture | Actual root representation |
| --- | --- |
| Ordinary PEP 621 source project | `source = { virtual = "." }` |
| PEP 621 package-mode project with setuptools/src layout | `source = { editable = "." }` |
| PEP 621 source project with selected `feature` extra | `source = { virtual = "." }`; metadata lists the extra |
| Build-system-only pyproject + literal setup.py, zero dependencies | **No package records** |
| Build-system-only pyproject + setup.cfg, zero dependencies | **No package records** |

Both actual legacy locks contain only `version = 1`, `revision = 3`, and
`requires-python = ">=3.12"`. Assessment identifies `legacy-demo` and source mode;
the backend-dependency blocker does not apply. Before this correction, generation
succeeded but `APPROVED_ARTIFACT_LOCK_IDENTITY` failed because no root identity
could be proved. Afterward, `LEGACY_LOCK_ROOT_UNIDENTIFIABLE` blocks planning and
generation, including an explicit dry-run action, before creating the kit.
The remedy is standardized `[project]` metadata and a regenerated lock.

A new TOML-only helper returns the exact name of one unambiguous virtual/editable
`.` root. Static validation cross-checks canonical distribution names from the
application artifact, standardized project metadata, and structural lock root;
contradictions fail closed. There is no application-ID/directory-name inference,
source reassessment, or metadata execution. Root-bearing older source manifests,
including synthetic legacy compatibility fixtures, remain valid. Such fixtures
are not claimed to be the output of the actual rootless uv legacy workflow.

Merely persisting the legacy name would not supply the absent root graph, so the
allowed early planning blocker is used instead of a new manifest field. Analysis
schema **1.4** and planning schema **1.3** remain unchanged. Static lock proof is
still unconditional: an empty approved-artifact list does not bypass reverse
artifact completeness.

## Read-only acceptance checks

| Repository | Unchanged SHA | Result |
| --- | --- | --- |
| SimpleGeorefGUI | `f484570d89fb1f9e9170fac915475358dfc1234e` | package; ENTRYPOINT_REQUIRES_PACKAGE_MODE; BLOCKED_PENDING_APPLICATION_WHEEL; 13 Python / 77 data members |
| Geo Map Explanation Extractor | `5e7b321d0aeb9ba1d586bfc548c79793d84c6033` | source / SOURCE_COMPATIBLE |
| TN Coordinate Converter | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` | source / SOURCE_COMPATIBLE; existing reviewed kit STATIC_VALID |

Before/after Git working-tree status also matched. Configuration-name lists did
not change: SGG has APPDATA, LOCALAPPDATA, SIMPLE_GEOREF_GUI_DATA_DIR, XDG_DATA_HOME;
Geo has LOCALAPPDATA and OPENAI_API_KEY; TN has none. No environment values are
included in this report. TN's existing kit retains the approved
`proxy_tools-0.1.0-py3-none-any.whl` artifact and `proxy-tools==0.1.0` identity.

## Verification

Focused final regression run: **127 passed, 430 deselected** (new regression file,
keyword wheel-secret propagation, and existing backend-only metadata cases).
The single complete suite passed: **998 passed, 3 skipped in 259.25 seconds**
(previous baseline: 874 passed, 3 skipped). `ruff check .` and
`git diff --check` passed. The final diff contains only the four corrections,
the bounded audit, regression tests, and this reproduction/acceptance evidence.

The complete suite retains coverage of the preceding keyword AST correction,
MANIFEST/include-package-data and setuptools-scm guards, exact sync contract,
approved-artifact identity/reverse completeness, mode-aware pip checks, entry
points, short secrets, LOCALAPPDATA ordering, wheel/dependency policy, resource
and inventory rules, package surfaces, wheel security/integrity/collisions,
provenance, prepare-lock/dry-run/reporting/rollback, and deterministic packaging.
