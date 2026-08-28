# SimpleGeorefGUI Milestone 6 analysis acceptance

This is an analysis acceptance record, not a deployment acceptance. Neither repository was
modified by the real-application run, and no SimpleGeorefGUI code was imported or executed.

## Baselines

- SimpleGeorefGUI: `a7118732a44e8c2124ae9040d3f57c351974d0db`
- Pre-M6 comparison assessment: PDB `c27416db1fbe80216edd6e57fb9a7282116010e2`
- M6 implementation baseline: PDB `c4361f620dafa75a0e7ae365489921202a527c14`
- Result: assessment `YELLOW`; planning reports produced with
  `BLOCKED_PENDING_ENTRYPOINT`

## Before and after

The pre-M6 assessment scanned every Python file beneath the inferred flat source root. It reported
57 distinct import observations, 12 runtime assumptions, and one conventional resource. Planning
raised immediately when no standardized entry point was present, so it produced no plan.

The M6 assessment used a typed repository inventory. It analyzed 13 application-source files while
separately inventorying deployment support, tests, documentation, examples/snippets, development
tooling, and ignored/local paths. It reported 35 scoped import observations, six application
runtime assumptions, 25 resource/path requirements, 21 concrete runtime-resource inventory paths,
and three source-adjacent mutable-state candidates. The focused semantic review replaced broad
asset-directory expansion with exact path-use evidence, so unreferenced files beneath an asset
directory are not promoted merely because the directory exists.

Notable production false positives removed because their only evidence came from excluded scopes
included:

- `customtkinter`, `PySimpleGUI`, `tkintermapview`, `matplotlib`, and historical map-picker module
  variants;
- ImageMagick `convert` and a dynamic subprocess command;
- Windows registry and `ctypes`/DLL-loading findings originating in deployment support;
- an old hard-coded absolute path;
- development/deployment-only imports such as `winreg`.

The remaining runtime findings have current application-source evidence: Tkinter, pywebview,
socket/urllib network behavior, browser opening, and `__file__`-relative paths.

## Resources and mutable state

M6 newly found high-confidence runtime resources including:

- 20 specifically referenced toolbar/icon/image files beneath `code/assets/`;
- `code/georef_agol_map.html`;

`code/georef_arcgis_oauth_session.json`, `code/georef_map_picker_state.json`, and
`code/georef_portal_settings.json` have actual static write/read-write evidence and are classified
as mutable local state rather than immutable resources. The report explains the portability
consequence of writing persistent state beside source and suggests a per-user state location
without moving it. Unresolved legacy/config path references remain explicit `NEEDS_VALIDATION`
evidence. An ignored, statically referenced immutable resource remains a typed generation blocker.

## Entry point and incomplete plan

Static AST evidence identifies:

`simple_georef_gui.py -> code.georef_main:main`

as a high-confidence GUI launcher candidate. Documentation also references that script. It is
explicitly non-authoritative: M6 does not execute it and does not use it for generation.

Both offline and online planning now write complete JSON and Markdown reports and return nonzero.
The plan exposes both safely known blockers:

- `ENTRYPOINT_DECLARATION_REQUIRED`;
- `LOCKFILE_GENERATION_REQUIRED`.

Generation remains prohibited until standardized metadata declares an entry point and the normal
developer-preparation/lock policy is satisfied.

## Legacy dependencies and online evidence

`requirements-core.txt`, `requirements-all.txt`, `requirements-optional.txt`, and
`requirements-arcgis-pro.txt` are reported as implicit legacy groups, not selectable extras.
Explicit include/superset relationships are descriptive only.

Online planning completes safe informational PyPI inspection despite the structural blocker. It
does not install or build anything. The evidence includes compatible wheels for Pillow, NumPy,
PyMuPDF, pyproj, pywebview, pythonnet, clr_loader, and arcgis for the evaluated targets. It also
reports:

- GDAL: source distribution present, no compatible Windows wheel detected;
- proxy_tools 0.1.0: source distribution present, no compatible wheel detected.

The pythonnet, clr_loader, and proxy_tools pins come from deployment-support constraints and are
not promoted to application launch requirements. Without standardized extras and a lockfile, PDB
cannot claim that any legacy group is the deployable feature selection or traverse an authoritative
transitive graph.

## Existing deployment and external/vendor runtimes

M6 separately inventories the existing Run, Repair, diagnostics, setup, verification, constraint,
registry-discovery, environment-clone, LocalAppData state, and fast-path support. Imports used only
by that machinery no longer pollute application runtime findings. Potential generated-filename and
`deployment/` collisions are reported before generation; normal generation collision checks remain
authoritative.

ArcGIS Pro is reported as a vendor-runtime candidate based on ESRI registry discovery,
`arcgispro-py3`, ArcPy, and environment-clone evidence. PDB does not assert that ArcGIS Pro is
required for core GUI launch. The assessment states that the current `uv_managed` backend cannot
reproduce or clone a vendor-managed ArcGIS Pro Python runtime.

Microsoft Edge WebView2 is reported as a feature-specific external Windows runtime from existing
map-picker diagnostics, with `required_for_core_launch=false`. It is detected, not silently
installed.

## Feature-boundary evidence and limits

The repository supports investigating a future split into core, map-picker, and ArcGIS-backed
features:

- Pillow is imported at module top level; NumPy, pyproj, and PyMuPDF are declared in the core
  requirements group;
- pywebview is imported in deferred feature code, while WebView2 has separate diagnostic evidence;
- `arcgis` and `osgeo` imports are deferred inside ArcGIS/export functionality;
- existing deployment support explicitly treats ArcGIS Pro as an environment template.

That evidence is not yet an authoritative feature model. Legacy requirement filenames do not
define selectable extras, imports alone do not prove every runtime path, GDAL/ArcPy/vendor package
compatibility is not representable by the current backend, and no lockfile provides a selected
transitive graph. SimpleGeorefGUI therefore remains not ready for current generic generation and
also exposes a genuine future ArcGIS Pro backend requirement for full ArcGIS-enabled deployment.

## Accepted M6 outcome

M6 improved diagnostic trust without making the application deployable by assumption:

- fewer false positives through role-aware scope;
- true resource and mutable-state evidence;
- entry-point candidate guidance without execution or authorization;
- useful blocked plans with multiple typed blockers;
- informational online evidence for legacy/deployment-support dependencies;
- application-source, deployment-support, WebView2, and ArcGIS Pro evidence kept distinct.
