"""Pinned synthetic builds for omitted project fields and dynamic script groups."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.planning.planner import create_deployment_plan


def main():
    uv = Path(sys.argv[1]).resolve()
    version = subprocess.check_output([str(uv), "--version"], text=True).strip()
    assert version.startswith("uv 0.12.5 "), version
    workspace = Path(tempfile.mkdtemp(prefix="pdb-omitted-authority-"))
    environment = dict(os.environ, UV_SYSTEM_CERTS="true", UV_NO_ENV_FILE="1", UV_NO_PROGRESS="1")
    print(version, workspace, flush=True)
    for legacy in ("setup.cfg", "setup.py"):
        for kind in (
            "omitted",
            "dynamic-console",
            "dynamic-gui",
            "both-console",
            "both-gui",
            "requires-python",
            "optional",
        ):
            root = workspace / (legacy + "-" + kind)
            root.mkdir()
            (root / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
            field = "scripts" if kind.endswith("console") else "gui-scripts"
            extra = f"dynamic=['{field}']\n" if kind.startswith(("dynamic", "both")) else ""
            if kind.startswith("both"):
                extra += f"[project.{field}]\nmodern='app:main'\n"
            (root / "pyproject.toml").write_text(
                "[build-system]\nrequires=['setuptools==79.0.1']\n"
                "build-backend='setuptools.build_meta'\n"
                "[project]\nname='demo'\nversion='1.0.0'\n" + extra,
                encoding="utf-8",
            )
            if legacy == "setup.cfg":
                contents = "[options]\npy_modules=app\n"
                if kind == "omitted":
                    contents += "install_requires=obsolete>=1\n"
                if kind == "requires-python":
                    contents += "python_requires=<3.10\n"
                contents += (
                    "[options.entry_points]\nconsole_scripts=\n stale-tool=app:main\n"
                    "gui_scripts=\n stale-gui=app:main\n"
                )
                if kind == "optional":
                    contents += "[options.extras_require]\nmap=obsolete>=1\n"
            else:
                keywords = ", install_requires=['obsolete>=1']" if kind == "omitted" else ""
                if kind == "requires-python":
                    keywords += ", python_requires='<3.10'"
                if kind == "optional":
                    keywords += ", extras_require={'map':['obsolete>=1']}"
                contents = (
                    "from setuptools import setup\nsetup(py_modules=['app'], entry_points={"
                    "'console_scripts':['stale-tool=app:main'], "
                    "'gui_scripts':['stale-gui=app:main']}"
                    + keywords
                    + ")\n"
                )
            (root / legacy).write_text(contents, encoding="utf-8")
            result = {"legacy": legacy, "kind": kind}
            for operation, arguments in (
                ("lock", ["lock", "--python", "3.12"]),
                (
                    "build",
                    ["build", "--wheel", "--python", "3.12", "--out-dir", str(root / "dist")],
                ),
            ):
                run = subprocess.run(
                    [str(uv), *arguments], cwd=root, env=environment, capture_output=True, text=True
                )
                result[operation + "_exit"] = run.returncode
                if run.returncode:
                    result[operation + "_error"] = run.stderr[-1300:]
            if (root / "uv.lock").exists():
                lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
                result["lock_packages"] = [p["name"] for p in lock.get("package", [])]
            if result["build_exit"] == 0:
                with zipfile.ZipFile(next((root / "dist").glob("*.whl"))) as bundle:
                    names = bundle.namelist()
                    metadata = BytesParser().parsebytes(
                        bundle.read(next(n for n in names if n.endswith(".dist-info/METADATA")))
                    )
                    result["requires_dist"] = metadata.get_all("Requires-Dist", [])
                    result["requires_python"] = metadata.get("Requires-Python")
                    result["generator"] = BytesParser().parsebytes(bundle.read(next(
                        n for n in names if n.endswith(".dist-info/WHEEL")
                    ))).get("Generator")
                    entries = next((n for n in names if n.endswith("/entry_points.txt")), None)
                    result["wheel_entries"] = bundle.read(entries).decode() if entries else ""
            try:
                assessment = assess_repository(
                    MaterializedRepository(root=root, source=str(root), source_kind="local")
                )
                plan = create_deployment_plan(assessment, repository_root=root)
                result["pdb_dependencies"] = [d.distribution_name for d in assessment.dependencies]
                result["pdb_entries"] = [e.name for e in assessment.project.entry_points]
                result["pdb_python"] = assessment.python.requires_python
                result["pdb_blockers"] = plan.risk_gate.blocking_codes
                result["pdb_entry"] = plan.entry_point.target if plan.entry_point else None
            except ValueError as error:
                result["pdb_error"] = str(error)
            print(json.dumps(result), flush=True)
            assert result["lock_exit"] == 0 and result["lock_packages"] == ["demo"], result
            assert "pdb_error" not in result, result
            assert result["pdb_dependencies"] == [] and result["pdb_python"] is None, result
            if kind.startswith(("dynamic", "both")):
                assert "ENTRYPOINT_METADATA_UNSUPPORTED" in result["pdb_blockers"], result
                expected_stale = "stale-tool" if field == "scripts" else "stale-gui"
                assert expected_stale in result["pdb_entries"], result
            else:
                assert result["pdb_entries"] == [], result
                assert "RUNTIME_SYNC_METADATA_UNSUPPORTED" not in result["pdb_blockers"], result
            if kind.startswith("both"):
                assert result["build_exit"] != 0 and "project.dynamic" in result["build_error"]
            elif kind == "requires-python":
                # Pinned setuptools itself crashes while clearing the stale field;
                # uv still creates a standardized lock without the legacy constraint.
                assert result["build_exit"] != 0 and "NoneType" in result["build_error"]
            else:
                assert result["build_exit"] == 0, result
                assert result["generator"] == "setuptools (79.0.1)", result
                assert result["requires_dist"] == [] and result["wheel_entries"] == "", result


if __name__ == "__main__":
    main()
