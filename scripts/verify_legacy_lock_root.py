"""Explicit developer acceptance: observe uv 0.12.5 roots without running application code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.validation.static import validate_static_kit


def main() -> None:
    uv = Path(sys.argv[1]).resolve()
    version = subprocess.check_output([str(uv), "--version"], text=True).strip()
    assert version.startswith("uv 0.12.5 "), version
    workspace = Path(tempfile.mkdtemp(prefix="pdb-legacy-root-"))
    print(version, workspace, flush=True)
    environment = os.environ.copy()
    environment.update(UV_SYSTEM_CERTS="true", UV_NO_ENV_FILE="1", UV_NO_PROGRESS="1")
    for kind in ("setup.py", "setup.cfg", "pep621", "package", "extra"):
        root = workspace / kind
        root.mkdir()
        build = (
            "[build-system]\nrequires=['setuptools==79.0.1']\n"
            "build-backend='setuptools.build_meta'\n"
        )
        (root / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
        if kind == "setup.py":
            metadata = (
                "from setuptools import setup\n"
                "setup(name='legacy-demo', version='1.0.0', py_modules=['app'], "
                "entry_points={'console_scripts':['legacy-demo=app:main']})\n"
            )
        elif kind == "setup.cfg":
            metadata = (
                "[metadata]\nname=legacy-demo\nversion=1.0.0\n"
                "[options]\npy_modules=app\n[options.entry_points]\n"
                "console_scripts=\n    legacy-demo=app:main\n"
            )
        else:
            metadata = ""
        if metadata:
            (root / kind).write_text(metadata, encoding="utf-8")
            pyproject = build
        else:
            pyproject = (
                "[project]\nname='legacy-demo'\nversion='1.0.0'\n"
                "requires-python='>=3.12'\n"
                "[project.scripts]\nlegacy-demo='app:main'\n"
            )
            if kind == "package":
                (root / "src/app").mkdir(parents=True)
                (root / "src/app/__init__.py").write_text("def main(): return 0\n")
                (root / "app.py").unlink()
                pyproject = build + pyproject + "[tool.setuptools]\npackage-dir={''='src'}\n"
            if kind == "extra":
                pyproject += "[project.optional-dependencies]\nfeature=[]\n"
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        subprocess.run(
            [str(uv), "lock", "--python", "3.12"],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
        repo = MaterializedRepository(root=root, source=str(root), source_kind="local")
        assessment = assess_repository(repo)
        plan = create_deployment_plan(
            assessment, repository_root=root, selected_extras=["feature"] if kind == "extra" else []
        )
        result = {
            "kind": kind,
            "packages": lock.get("package"),
            "distribution": assessment.project.distribution_name,
            "mode": plan.deployment_mode,
            "condition": plan.deployment_mode_condition,
            "blocking_codes": plan.risk_gate.blocking_codes,
        }
        if metadata:
            kit = workspace / (kind + "-kit")
            try:
                generate_deployment_kit(repo, kit, bootstrap_mode="online_cmd", system_certs=True)
            except PreparationError as exc:
                assert "LEGACY_LOCK_ROOT_UNIDENTIFIABLE" in str(exc)
                assert not kit.exists()
                result["generation_blocker"] = str(exc)
            else:
                report = validate_static_kit(kit)
                result["static"] = report.final_state.value
                result["failures"] = [
                    item.model_dump(mode="json")
                    for item in report.static_checks
                    if item.status.value == "FAIL"
                ]
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
