"""Explicit synthetic setuptools 79.0.1 / uv 0.12.5 dependency-authority experiment."""

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

from verify_approved_extra_context import wheel

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.planning.planner import create_deployment_plan


def main() -> None:
    uv = Path(sys.argv[1]).resolve()
    version = subprocess.check_output([str(uv), "--version"], text=True).strip()
    assert version.startswith("uv 0.12.5 "), version
    workspace = Path(tempfile.mkdtemp(prefix="pdb-dependency-authority-"))
    artifacts = workspace / "input-wheels"
    artifacts.mkdir()
    for name in ("modern", "obsolete"):
        wheel(artifacts, name, [], [])
    environment = os.environ.copy()
    environment.update(UV_SYSTEM_CERTS="true", UV_NO_ENV_FILE="1", UV_NO_PROGRESS="1")
    print(version, workspace, flush=True)
    for legacy in ("setup.cfg", "setup.py"):
        for kind in ("nonempty", "empty", "static-dynamic", "dynamic-only", "scripts"):
            if len(sys.argv) > 2 and kind not in sys.argv[2:]:
                continue
            root = workspace / (legacy + "-" + kind)
            root.mkdir()
            (root / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
            field = "dependencies=['modern>=1']\n"
            if kind == "empty":
                field = "dependencies=[]\n"
            if kind == "static-dynamic":
                field += "dynamic=['dependencies']\n"
            if kind == "dynamic-only":
                field = "dynamic=['dependencies']\n"
            (root / "pyproject.toml").write_text(
                "[build-system]\nrequires=['setuptools==79.0.1']\n"
                "build-backend='setuptools.build_meta'\n"
                "[project]\nname='demo'\nversion='1.0.0'\nrequires-python='>=3.12'\n"
                + field
                + (
                    "[project.scripts]\ndemo='app:main'\n[project.gui-scripts]\n"
                    if kind == "scripts"
                    else "[project.gui-scripts]\ndemo='app:main'\n"
                ),
                encoding="utf-8",
            )
            if legacy == "setup.cfg":
                contents = "[options]\npy_modules=app\ninstall_requires=\n    obsolete>=1\n"
                if kind == "scripts":
                    contents += "[options.entry_points]\ngui_scripts=\n    obsolete=old:main\n"
            else:
                extra = (
                    ", entry_points={'gui_scripts':['obsolete=old:main']}"
                    if kind == "scripts"
                    else ""
                )
                contents = (
                    "from setuptools import setup\n"
                    "setup(py_modules=['app'], install_requires=['obsolete>=1']" + extra + ")\n"
                )
            (root / legacy).write_text(contents, encoding="utf-8")
            result = {"legacy": legacy, "kind": kind}
            lock = subprocess.run(
                [str(uv), "lock", "--python", "3.12", "--find-links", str(artifacts)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
            )
            result["lock_exit"] = lock.returncode
            if lock.returncode:
                result["lock_error"] = lock.stderr[-2200:]
            else:
                document = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
                result["locked_packages"] = [p["name"] for p in document.get("package", [])]
            build = subprocess.run(
                [str(uv), "build", "--wheel", "--python", "3.12", "--out-dir", str(root / "dist")],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
            )
            result["build_exit"] = build.returncode
            if build.returncode:
                result["build_error"] = build.stderr[-2200:]
            else:
                with zipfile.ZipFile(next((root / "dist").glob("*.whl"))) as bundle:
                    names = bundle.namelist()
                    metadata = BytesParser().parsebytes(
                        bundle.read(next(n for n in names if n.endswith(".dist-info/METADATA")))
                    )
                    result["requires_dist"] = metadata.get_all("Requires-Dist", [])
                    result["wheel"] = bundle.read(
                        next(n for n in names if n.endswith(".dist-info/WHEEL"))
                    ).decode()
                    result["entry_points"] = bundle.read(
                        next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
                    ).decode()
            assessment = assess_repository(
                MaterializedRepository(root=root, source=str(root), source_kind="local")
            )
            plan = create_deployment_plan(assessment, repository_root=root)
            result["pdb_dependencies"] = [d.distribution_name for d in assessment.dependencies]
            result["pdb_blockers"] = plan.risk_gate.blocking_codes
            result["pdb_entry_point"] = plan.entry_point.target if plan.entry_point else None
            print(json.dumps(result), flush=True)
            blocked = "RUNTIME_SYNC_METADATA_UNSUPPORTED" in result["pdb_blockers"]
            if kind == "static-dynamic":
                assert lock.returncode and build.returncode, result
                assert "project.dynamic" in lock.stderr, result
                assert blocked and "obsolete" in result["pdb_dependencies"], result
            else:
                assert lock.returncode == build.returncode == 0, result
                expected = (
                    []
                    if kind == "empty"
                    else ["obsolete"]
                    if kind == "dynamic-only"
                    else ["modern"]
                )
                assert sorted(result["locked_packages"]) == sorted(["demo", *expected]), result
                assert result["requires_dist"] == [f"{name}>=1" for name in expected], result
                assert "setuptools (79.0.1)" in result["wheel"], result
                assert result["pdb_dependencies"] == expected, result
                assert blocked == (kind == "dynamic-only"), result
                assert result["pdb_entry_point"] == "app:main", result
                if kind == "scripts":
                    assert "obsolete" not in result["entry_points"], result


if __name__ == "__main__":
    main()
