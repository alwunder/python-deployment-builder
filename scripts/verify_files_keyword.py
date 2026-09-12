"""Probe files() keyword compatibility on explicitly selected Python runtimes."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROBE = """
import json, sys, warnings
from importlib.resources import files
from app.probe import implicit
result = {'version': sys.version.split()[0]}
for name, call in [
    ('positional', lambda: files('app')),
    ('package', lambda: files(package='app')),
    ('anchor', lambda: files(anchor='app')),
    ('implicit', implicit),
]:
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter('always')
        try:
            result[name] = {'read': call().joinpath('defaults.json').read_text()}
        except Exception as error:
            result[name] = {'error': type(error).__name__}
        result[name]['warnings'] = [type(w.message).__name__ for w in seen]
assert result['package']['read'] == '{}'
if sys.version_info[:2] == (3, 11):
    assert result['anchor']['error'] == 'TypeError'
    assert result['implicit']['error'] == 'TypeError'
else:
    assert result['anchor']['read'] == result['implicit']['read'] == '{}'
    assert result['package']['warnings'] == ['DeprecationWarning']
print(json.dumps(result))
"""


def main():
    uv = str(Path(sys.argv[1]).resolve())
    root = Path(tempfile.mkdtemp(prefix="pdb-files-keyword-"))
    package = root / "app"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "defaults.json").write_text("{}")
    (package / "probe.py").write_text(
        "from importlib.resources import files\ndef implicit(): return files()\n"
    )
    environment = dict(os.environ, PYTHONPATH=str(root), UV_SYSTEM_CERTS="true")
    for version in ("3.11", "3.12"):
        run = subprocess.run(
            [
                uv,
                "run",
                "--no-project",
                "--no-config",
                "--managed-python",
                "--python",
                version,
                "python",
                "-B",
                "-c",
                PROBE,
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
        )
        print(
            json.dumps(
                {
                    "requested": version,
                    "exit": run.returncode,
                    "stdout": run.stdout,
                    "stderr": run.stderr,
                }
            ),
            flush=True,
        )
        assert run.returncode == 0
    run = subprocess.run(
        [sys.executable, "-B", "-c", PROBE],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )
    print(run.stdout, run.stderr, flush=True)
    assert run.returncode == 0


if __name__ == "__main__":
    main()
