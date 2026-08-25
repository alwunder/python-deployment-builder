# Tennessee Coordinate Converter Windows acceptance — 2026-08-24

## Scope and traceability

This record covers the second real end-user acceptance of Python Deployment Builder's Windows
`uv_managed` backend. Tennessee Coordinate Converter exercises a materially different application
shape from Geo Map Exp Extractor. Together they establish broader pilot evidence, but they do not
claim universal Windows compatibility.

| Item | Accepted value |
| --- | --- |
| Application | Tennessee Coordinate Converter v1.0.0 |
| Final TN source | `e1e7a1588c37a99c2d02efaf3eef3d04636f12f0` |
| Final release | [`v1.0.0`](https://github.com/alwunder/tn-coordinate-converter/releases/tag/v1.0.0) |
| Release ZIP SHA-256 | `F15C4311278379FA788598BA6B5FD9E1B47B69AE85A3B7633CB4BCB50A124122` |
| Python Deployment Builder | 0.1.0 at `5295f60a424200fd77a851b5d61bfc97a883a80e` |
| Account type | Windows Standard User |
| Bootstrap | bundled uv 0.12.5 |
| Managed runtime | CPython 3.12.14 |
| Environment policy | locked, `--no-build`, selected `map` extra, no development extra |
| Elevation | not requested or required |
| PowerShell | not used or required |

The final package was generated from clean merged main branches and published as a GitHub Release
asset rather than committed to either repository. The uploaded 21,687,529-byte ZIP was downloaded
again after publication and independently verified against the SHA-256 above.

## Deployment features exercised

Acceptance covered:

- a flat-module source application;
- Windows Standard User setup without administrator privileges;
- verified bundled uv and per-user managed CPython;
- Windows system certificates for network operations;
- an explicitly selected optional `map` extra;
- `pywebview`, `pythonnet`, and `clr-loader`;
- Microsoft Edge WebView2 as an external Windows runtime;
- an NGMDB MapView child window;
- a source-only locked transitive dependency and approved developer-built wheel;
- end-user locked/no-build synchronization;
- Repair reinstalling the approved artifact;
- a GUI entry point that uses `argparse`;
- fast subsequent launch, diagnostics, staleness, rollback, and scoped repair.

Manual application checks included representative coordinate conversion, Carter conversion, batch
and UI behavior, DD/DDM/DMS geographic input and copy formats, Carter Quadrant versus Footage
behavior, revised About/Help rendering and navigation, View on Map, and NGMDB MapView.

## Approved source-only dependency artifact

The selected map graph contained `pywebview -> proxy-tools==0.1.0`. The public locked dependency
remained source-distribution-only, so normal production generation correctly required an approved
developer artifact rather than permitting a source build on the end-user machine.

| Artifact | SHA-256 |
| --- | --- |
| Reviewed `proxy_tools==0.1.0` source distribution | `CCB3751F529C047E2D8A58440D86B205303CF0FE8146F784D1CBCD94F0A28010` |
| Approved `proxy_tools-0.1.0-py3-none-any.whl` | `2431971DBCA4CF6524F851BF7F9D9E3275EF64F0C5607AD39B348DF05FF97BC5` |

The exact source distribution was inspected developer-side. A pure-Python wheel was then built and
explicitly approved without modifying the package source. The end-user environment retained the
global `--no-build` policy: generated setup excluded the named package from locked sync, installed
the verified local wheel with exact no-dependency/no-build semantics, and ran `uv pip check`.
Repair reused the same recorded wheel and hash deterministically.

## First TN manual test: setup succeeded, GUI did not appear

The first Standard User test successfully completed:

- managed Python provisioning;
- locked/no-build dependency synchronization;
- installation of the map dependencies and approved `proxy_tools` wheel;
- `uv pip check` and launch-callable checking;
- deployment-state recording;
- WebView2 detection;
- Diagnose and Repair.

Despite that successful setup, the application GUI did not appear.

### Root cause

The generated launch helper parsed its private `--project-root` argument and then invoked TN's
`argparse`-based `main()` without isolating process-global `sys.argv`. TN therefore received the
builder's internal helper argument. Its parser rejected the unknown option and exited before
`tk.Tk()` was created. Normal GUI launch used `pythonw.exe`, so the parser error was initially not
visible in a console.

### Generic builder fix

Python Deployment Builder was corrected generically; TN was not changed to recognize a private
deployment argument. The builder now:

- separates application `sys.argv` from deployment-helper arguments;
- preserves applications that do not inspect arguments and supports argparse-based entry points;
- records early GUI entry-point failures in the application's per-user log directory;
- reports the most recent application launch failure through Diagnose;
- uses real generated-helper subprocess tests to exercise the production `-B -E -s` invocation
  contract and argument isolation.

## Second manual acceptance after the generic fix

After regeneration with the generic builder fix:

- the GUI opened without elevation;
- representative and Carter conversions passed;
- View on Map opened and NGMDB MapView worked;
- fast relaunch passed;
- Diagnose and Repair passed;
- conversion and MapView worked after Repair;
- Repair restored the selected extra and approved wheel under locked/no-build policy;
- no application-launch-failure log was created during successful operation.

## Final release smoke after application UI updates

TN subsequently added geographic DD/DDM/DMS input and copy formats, Carter Quadrant versus Footage
behavior, batch/JSON refinements, and improved About/Help Markdown rendering and navigation. These
changes did not alter `pyproject.toml`, `uv.lock`, the selected extra, or the approved artifact.

The final release artifact was regenerated from clean merged main at the source commit recorded
above. Static and isolated runtime validation passed. The final Standard User smoke test confirmed:

- GUI launch without elevation;
- representative conversion and updated geographic input/copy behavior;
- Carter Quadrant and Footage UI behavior;
- correctly rendered About/Help content and working internal navigation;
- View on Map and NGMDB MapView;
- fast relaunch;
- current Diagnose state, detected WebView2, the approved artifact, and no launch failure;
- locked/no-build Repair, `uv pip check`, launch check, and restored map behavior.

## Result

Tennessee Coordinate Converter v1.0.0 is the second real application accepted with the Windows
`uv_managed` backend. It demonstrates support for a flat-module desktop application, optional
native/runtime integration, a reviewed source-only dependency artifact, and an argparse-based GUI
entry point. The backend remains **pilot ready**, not universally compatible: new applications
still require repository assessment, locked-artifact review, developer-side validation, and
representative Standard User testing in their intended organizational environment.
