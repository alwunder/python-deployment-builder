# Static deployment assessment

**Rating: YELLOW** — Likely deployable, but configuration, resource, write-location, lock, or runtime compatibility findings need attention.

- Schema version: `1.0`
- Generated: `2026-08-19T18:48:26.381223+00:00`
- Repository source: `https://github.com/alwunder/geo-map-exp-extractor`
- Repository fingerprint: `f9112964e1238f7e9080130cd74b7cdf11e81c0bd2a1d84ae6d15f22f054d8a8`
- Project: `geo-map-exp-extractor`
- Packaging layout: `src`

## Packaging and entry points

| Name | Kind | Target |
|---|---|---|
| `geo-map-exp-extractor` | cli | `geo_map_exp_extractor.cli:app` |
| `geo-image-extract-gui` | gui | `geo_map_exp_extractor.gui:main` |

## Python requirements

- `requires-python`: `>=3.11`
- `.python-version`: `not present`
- Ruff target: `py311`
- Documented versions: `3.11`

The assessment records compatibility evidence only. Runtime selection is a planner policy decision.

## Declared dependencies

| Distribution | Constraint | Group | Imports | Implementation | Windows concern | Wheel status |
|---|---|---|---|---|---|---|
| `pytest` | `>=8.0.0` | dev | `pytest` | pure_python | low | not_assessed |
| `ruff` | `>=0.6.0` | dev | `ruff` | unknown | unknown | not_assessed |
| `openai` | `>=2.0.0` | runtime | `openai` | pure_python | low | not_assessed |
| `Pillow` | `>=10.0.0` | runtime | `PIL` | native_or_compiled | medium | not_assessed |
| `pydantic` | `>=2.0.0` | runtime | `pydantic` | native_or_compiled | medium | not_assessed |
| `PyYAML` | `>=6.0.0` | runtime | `yaml` | native_or_compiled | medium | not_assessed |
| `rich` | `>=13.0.0` | runtime | `rich` | pure_python | low | not_assessed |
| `tksheet` | `>=7.4.0` | runtime | `tksheet` | pure_python | low | not_assessed |
| `typer` | `>=0.12.0` | runtime | `typer` | pure_python | low | not_assessed |

## Import mismatches

No observed application-source imports were left unmatched to the standard library, local modules, or declared dependencies.

## Runtime assumptions

- **detected — external_executable: open.** Application may invoke external command 'open'. Evidence: `src/geo_map_exp_extractor/gui.py:1895` — Called subprocess.run.
- **detected — external_executable: xdg-open.** Application may invoke external command 'xdg-open'. Evidence: `src/geo_map_exp_extractor/gui.py:1897` — Called subprocess.run.
- **detected — external_launcher: os.startfile.** Application delegates opening a path/URL through os.startfile. Evidence: `src/geo_map_exp_extractor/gui.py:1893` — Called os.startfile.
- **detected — gui_toolkit: Tkinter.** Application source uses Tkinter; availability must be verified in the managed runtime. Evidence: `src/geo_map_exp_extractor/gui.py:10` — Imported GUI toolkit.; `src/geo_map_exp_extractor/gui.py:14` — Imported GUI toolkit.
- **detected — network: openai.** Application source uses openai, indicating network or remote-service behavior. Evidence: `src/geo_map_exp_extractor/openai_runner.py:168` — Imported network/API module.
- **detected — path_assumption: current working directory.** Application has a runtime path assumption: current working directory. Evidence: `src/geo_map_exp_extractor/cli.py:23` — Called Path.cwd.; `src/geo_map_exp_extractor/gui.py:129` — Called Path.cwd.; `src/geo_map_exp_extractor/gui.py:139` — Called Path.cwd.; `src/geo_map_exp_extractor/openai_runner.py:184` — Called Path.cwd.
- **detected — path_assumption: repository-root derived from __file__.** Application has a runtime path assumption: repository-root derived from __file__. Evidence: `src/geo_map_exp_extractor/cli.py:22` — Source path participates in runtime path construction.; `src/geo_map_exp_extractor/gui.py:25` — Source path participates in runtime path construction.; `src/geo_map_exp_extractor/gui.py:134` — Source path participates in runtime path construction.; `src/geo_map_exp_extractor/jobs.py:67` — Source path participates in runtime path construction.
- **detected — subprocess: subprocess.** Application source can create child processes. Evidence: `src/geo_map_exp_extractor/gui.py:7` — Imported subprocess module.

## Repository resources

- **inferred: `.env.example`** — configuration_example; repository_adjacent; read. Evidence: `.env.example` — Repository resource exists outside the import package.
- **detected: `examples`** — examples; repository_adjacent; read. Evidence: `examples` — Repository resource exists outside the import package.; `src/geo_map_exp_extractor/jobs.py:375` — Resource path literal 'examples'.
- **detected: `profiles`** — profiles; repository_adjacent; read. Evidence: `profiles` — Repository resource exists outside the import package.; `src/geo_map_exp_extractor/gui.py:128` — Resource path literal 'profiles'.; `src/geo_map_exp_extractor/gui.py:129` — Resource path literal 'profiles'.
- **detected: `prompts`** — prompts; repository_adjacent; read. Evidence: `prompts` — Repository resource exists outside the import package.; `src/geo_map_exp_extractor/cli.py:77` — Resource path literal 'prompts/extraction_prompt.md'.; `src/geo_map_exp_extractor/cli.py:183` — Resource path literal 'prompts/extraction_prompt.md'.; `src/geo_map_exp_extractor/jobs.py:67` — Resource path literal 'prompts'.
- **detected: `README.md`** — documentation; repository_adjacent; read. Evidence: `README.md` — Repository resource exists outside the import package.; `src/geo_map_exp_extractor/gui.py:1520` — Resource path literal 'README.md'.

## Runtime writes

- **inferred: external_user_selected** — `destination = Path(output_dir)`. Evidence: `src/geo_map_exp_extractor/jobs.py:417` — Potential write operation: destination.mkdir (inferred).
- **inferred: external_user_selected** — `output_root = Path(output_dir)`. Evidence: `src/geo_map_exp_extractor/image_io.py:109` — Potential write operation: output_root.mkdir (inferred).
- **inferred: external_user_selected** — `root = Path(output_dir)`. Evidence: `src/geo_map_exp_extractor/image_io.py:178` — Potential write operation: root.mkdir (inferred).
- **inferred: external_user_selected** — `run_dir = _unique_run_dir(destination, run_id)`. Evidence: `src/geo_map_exp_extractor/jobs.py:426` — Potential write operation: run_dir.mkdir (inferred).
- **inferred: project_local** — `cache_file = _cache_file_path(request_hash)`. Evidence: `src/geo_map_exp_extractor/jobs.py:153` — Potential write operation: cache_file.write_text (inferred).
- **inferred: project_local** — `cache_file.parent`. Evidence: `src/geo_map_exp_extractor/jobs.py:152` — Potential write operation: cache_file.parent.mkdir (inferred).
- **inferred: project_local** — `self.output_dir = tk.StringVar(value=self._display_path(self._repo_root() / 'outputs'))`. Evidence: `src/geo_map_exp_extractor/gui.py:63` — Repository-local default output location.
- **needs_validation: unknown** — `Path(self.result.output_paths['notes'])`. Evidence: `src/geo_map_exp_extractor/gui.py:1816` — Potential write operation: write_text (needs_validation).
- **needs_validation: unknown** — `csv_target = target_prefix.with_suffix('.corrected.csv')`. Evidence: `src/geo_map_exp_extractor/jobs.py:382` — Potential write operation: shutil.copy2 (needs_validation).
- **needs_validation: unknown** — `json_target = target_prefix.with_suffix('.corrected.json')`. Evidence: `src/geo_map_exp_extractor/jobs.py:381` — Potential write operation: shutil.copy2 (needs_validation).
- **needs_validation: unknown** — `path = Path(output_path)`. Evidence: `src/geo_map_exp_extractor/exporters.py:27` — Potential write operation: path.open (needs_validation).; `src/geo_map_exp_extractor/exporters.py:53` — Potential write operation: path.write_text (needs_validation).; `src/geo_map_exp_extractor/exporters.py:62` — Potential write operation: path.write_text (needs_validation).; `src/geo_map_exp_extractor/jobs.py:322` — Potential write operation: path.open (needs_validation).
- **needs_validation: unknown** — `path.parent`. Evidence: `src/geo_map_exp_extractor/exporters.py:26` — Potential write operation: path.parent.mkdir (needs_validation).; `src/geo_map_exp_extractor/exporters.py:52` — Potential write operation: path.parent.mkdir (needs_validation).; `src/geo_map_exp_extractor/exporters.py:61` — Potential write operation: path.parent.mkdir (needs_validation).; `src/geo_map_exp_extractor/jobs.py:321` — Potential write operation: path.parent.mkdir (needs_validation).
- **needs_validation: unknown** — `paths['notes']`. Evidence: `src/geo_map_exp_extractor/jobs.py:466` — Potential write operation: write_text (needs_validation).
- **needs_validation: unknown** — `paths['profile']`. Evidence: `src/geo_map_exp_extractor/jobs.py:192` — Potential write operation: shutil.copy2 (needs_validation).
- **needs_validation: unknown** — `processed_path = output_root / f'processed_api_image{processed_suffix}'`. Evidence: `src/geo_map_exp_extractor/image_io.py:136` — Potential write operation: processed_path.write_bytes (needs_validation).
- **needs_validation: unknown** — `profile_folder = root / profile_id`. Evidence: `src/geo_map_exp_extractor/jobs.py:377` — Potential write operation: profile_folder.mkdir (needs_validation).
- **needs_validation: unknown** — `source_image_path = paths['source_image'].with_suffix(image_path.suffix)`. Evidence: `src/geo_map_exp_extractor/jobs.py:191` — Potential write operation: shutil.copy2 (needs_validation).

## Configuration and secrets

- **detected: `OPENAI_API_KEY`** — environment_variable, secret-bearing. Environment variable is read by application source; timing/necessity requires validation. Evidence: `src/geo_map_exp_extractor/gui.py:157` — Read through os.environ.get.; `src/geo_map_exp_extractor/gui.py:246` — Read through os.environ.get.; `src/geo_map_exp_extractor/gui.py:277` — Read through os.environ.get.; `src/geo_map_exp_extractor/gui.py:291` — Read through os.environ.get.
- **detected: `.env.example`** — dotenv, non-secret or example. Example dotenv file documents configuration; real .env contents must never be copied. Evidence: `.env.example` — Example configuration file exists.

## Risks and recommendations

### WARNING: No supported dependency lockfile (`DEPENDENCY_LOCK_MISSING`)

End-user installation cannot yet use a frozen resolution.

Recommendation: Generate and review uv.lock during developer-side deployment preparation.

### WARNING: Native or compiled dependencies need Windows wheel verification (`NATIVE_WHEELS_UNVERIFIED`)

Offline static analysis did not verify compatible Windows wheels for: Pillow, pydantic, PyYAML

Recommendation: Perform explicit online index assessment for the selected CPython minor and architecture.

Evidence: `pyproject.toml:16` — Declared in [project].dependencies.; `pyproject.toml:14` — Declared in [project].dependencies.; `pyproject.toml:15` — Declared in [project].dependencies.

### WARNING: Runtime behavior depends on repository-adjacent resources (`REPOSITORY_ADJACENT_RESOURCES`)

A conventional detached wheel install may not preserve required files: examples, profiles, prompts, README.md

Recommendation: Prefer source-based deployment initially or package resources deliberately in the application.

Evidence: `src/geo_map_exp_extractor/jobs.py:375` — Resource path literal 'examples'.; `src/geo_map_exp_extractor/gui.py:128` — Resource path literal 'profiles'.; `src/geo_map_exp_extractor/gui.py:129` — Resource path literal 'profiles'.; `src/geo_map_exp_extractor/cli.py:77` — Resource path literal 'prompts/extraction_prompt.md'.

### WARNING: Application may write under the extracted repository (`PROJECT_LOCAL_WRITES`)

No-admin deployment is viable only if the extracted project/output locations are writable.

Recommendation: Probe write access at startup and consider user-local defaults in the application.

Evidence: `src/geo_map_exp_extractor/jobs.py:153` — Potential write operation: cache_file.write_text (inferred).; `src/geo_map_exp_extractor/jobs.py:152` — Potential write operation: cache_file.parent.mkdir (inferred).; `src/geo_map_exp_extractor/gui.py:63` — Repository-local default output location.

### WARNING: Secret-bearing configuration is used (`SECRET_CONFIGURATION`)

Deployment must preserve configuration behavior without copying, embedding, or logging values.

Recommendation: Record names and presence only; never persist secret values in deployment state.

Evidence: `src/geo_map_exp_extractor/gui.py:157` — Read through os.environ.get.; `src/geo_map_exp_extractor/gui.py:246` — Read through os.environ.get.


## Analysis boundaries

- Static assessment did not import or execute target-project code.
- Package index and Windows wheel availability were not queried.
- Import-to-distribution matching uses declared metadata plus a conservative mapping table.
- Write-location and launch-critical classifications are heuristic until runtime validation.
