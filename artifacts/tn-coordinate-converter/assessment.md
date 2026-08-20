# Static deployment assessment

**Rating: YELLOW** — Likely deployable, but configuration, resource, write-location, lock, or runtime compatibility findings need attention.

- Schema version: `1.0`
- Generated: `2026-08-20T03:50:33.082940+00:00`
- Repository source: `https://github.com/alwunder/tn-coordinate-converter`
- Repository fingerprint: `714a926321fba5a3fd6b2bc982a4ad610d15a0138203ad2ab241879bd29a9fe8`
- Project: `tn-coordinate-converter`
- Packaging layout: `flat`

## Packaging and entry points

| Name | Kind | Target |
|---|---|---|
| `tn-coordinate-converter` | gui | `tn_coord_converter_gui:main` |
| `tn-coordinate-converter-gui` | gui | `tn_coord_converter_gui:main` |

## Python requirements

- `requires-python`: `>=3.10`
- `.python-version`: `not present`
- Ruff target: `py310`
- Documented versions: `3.10, 3.12`

The assessment records compatibility evidence only. Runtime selection is a planner policy decision.

## Declared dependencies

| Distribution | Constraint | Marker | Group | Imports | Implementation | Windows concern | Wheel status |
|---|---|---|---|---|---|---|---|
| `pytest` | `<10,>=8` | `all` | dev | `pytest` | pure_python | low | not_assessed |
| `ruff` | `<1,>=0.9` | `all` | dev | `ruff` | unknown | unknown | not_assessed |
| `clr-loader` | `<1,>=0.2` | `sys_platform == "win32"` | map | `clr_loader` | unknown | unknown | not_assessed |
| `pythonnet` | `<4,>=3.0` | `sys_platform == "win32"` | map | `pythonnet` | unknown | unknown | not_assessed |
| `pywebview` | `<7,>=6.1` | `sys_platform == "win32"` | map | `webview` | unknown | unknown | not_assessed |
| `pyproj` | `<4,>=3.7` | `all` | runtime | `pyproj` | native_or_compiled | medium | not_assessed |

## Import mismatches

No observed application-source imports were left unmatched to the standard library, local modules, or declared dependencies.

## Runtime assumptions

- **detected — external_executable: dynamic subprocess command.** Application may invoke external command 'dynamic subprocess command'. Evidence: `ngmdb_mapview_window.py:526` — Called subprocess.Popen.; `tn_coord_converter_gui.py:314` — Called subprocess.Popen.
- **detected — gui_toolkit: pywebview.** Application source uses pywebview; availability must be verified in the managed runtime. Evidence: `ngmdb_mapview_window.py:423` — Imported GUI toolkit.
- **detected — gui_toolkit: Tkinter.** Application source uses Tkinter; availability must be verified in the managed runtime. Evidence: `ngmdb_mapview_window.py:9` — Imported GUI toolkit.; `ngmdb_mapview_window.py:11` — Imported GUI toolkit.; `tn_coord_converter_gui.py:43` — Imported GUI toolkit.; `tn_coord_converter_gui.py:44` — Imported GUI toolkit.
- **detected — path_assumption: repository-root derived from __file__.** Application has a runtime path assumption: repository-root derived from __file__. Evidence: `ngmdb_mapview_window.py:529` — Source path participates in runtime path construction.; `tn_coord_converter_gui.py:98` — Source path participates in runtime path construction.; `tn_coord_converter_gui.py:295` — Source path participates in runtime path construction.
- **detected — subprocess: subprocess.** Application source can create child processes. Evidence: `ngmdb_mapview_window.py:4` — Imported subprocess module.; `tn_coord_converter_gui.py:22` — Imported subprocess module.

## Repository resources

- **detected: `README.md`** — documentation; repository_adjacent; read. Evidence: `README.md` — Repository resource exists outside the import package.; `tn_coord_converter_gui.py:83` — Resource path literal 'README.md'.

## Runtime writes

- **needs_validation: unknown** — `error_path = Path(command_file).with_suffix('.mapview-error.log')`. Evidence: `tn_coord_converter_gui.py:1581` — Potential write operation: error_path.write_text (needs_validation).
- **needs_validation: unknown** — `path`. Evidence: `tn_coord_converter_gui.py:876` — Potential write operation: path.open (needs_validation).; `tn_coord_converter_gui.py:887` — Potential write operation: path.open (needs_validation).
- **needs_validation: unknown** — `path.parent`. Evidence: `ngmdb_mapview_window.py:21` — Potential write operation: path.parent.mkdir (needs_validation).; `tn_coord_converter_gui.py:280` — Potential write operation: path.parent.mkdir (needs_validation).
- **needs_validation: unknown** — `tmp_path = path.with_suffix(path.suffix + '.tmp')`. Evidence: `ngmdb_mapview_window.py:23` — Potential write operation: tmp_path.write_text (needs_validation).; `tn_coord_converter_gui.py:282` — Potential write operation: tmp_path.write_text (needs_validation).

## Configuration and secrets

No configuration requirements were detected.

## Risks and recommendations

### WARNING: Native or compiled dependencies need Windows wheel verification (`NATIVE_WHEELS_UNVERIFIED`)

Offline static analysis did not verify compatible Windows wheels for: pyproj

Recommendation: Perform explicit online index assessment for the selected CPython minor and architecture.

Evidence: `pyproject.toml:24` — Declared in [project].dependencies.

### WARNING: Runtime behavior depends on repository-adjacent resources (`REPOSITORY_ADJACENT_RESOURCES`)

A conventional detached wheel install may not preserve required files: README.md

Recommendation: Prefer source-based deployment initially or package resources deliberately in the application.

Evidence: `tn_coord_converter_gui.py:83` — Resource path literal 'README.md'.


## Analysis boundaries

- Static assessment did not import or execute target-project code.
- Package index and Windows wheel availability were not queried.
- Import-to-distribution matching uses declared metadata plus a conservative mapping table.
- Write-location and launch-critical classifications are heuristic until runtime validation.
