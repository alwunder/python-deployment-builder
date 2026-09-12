"""Explicit offline uv 0.12.5 experiment: root lineage versus package extras."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from python_deployment_builder.planning.lockfile import inspect_uv_lock


def wheel(root: Path, name: str, requirements: list[str], extras: list[str]) -> str:
    normalized = name.replace("-", "_")
    info = f"{normalized}-1.dist-info"
    files = {
        f"{info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1\n"
            + "".join(f"Provides-Extra: {extra}\n" for extra in extras)
            + "".join(f"Requires-Dist: {item}\n" for item in requirements)
            + "\n"
        ).encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{normalized}/__init__.py": b"",
    }
    record = "".join(
        f"{path},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')},{len(data)}\n"
        for path, data in files.items()
    )
    files[f"{info}/RECORD"] = (record + f"{info}/RECORD,,\n").encode()
    filename = f"{normalized}-1-py3-none-any.whl"
    with zipfile.ZipFile(root / filename, "w") as bundle:
        for path, data in files.items():
            bundle.writestr(path, data)
    return filename


def main() -> None:
    uv = Path(sys.argv[1]).resolve()
    version = subprocess.check_output([str(uv), "--version"], text=True).strip()
    assert version.startswith("uv 0.12.5 "), version
    root = Path(tempfile.mkdtemp(prefix="pdb-approved-extra-context-"))
    print(version, root, flush=True)
    for name, requirements, extras in [
        ("pywebview", ["proxy-tools[feature]>=1"], []),
        (
            "proxy-tools",
            ["helper>=1", "optional-helper>=1; extra == 'feature' and sys_platform == 'win32'"],
            ["feature"],
        ),
        ("helper", [], []),
        ("optional-helper", [], []),
    ]:
        wheel(root, name, requirements, extras)
    (root / "pyproject.toml").write_text(
        "[project]\nname='app'\nversion='1'\nrequires-python='>=3.12'\n"
        "[project.optional-dependencies]\nmap=['pywebview']\n",
        encoding="utf-8",
    )
    subprocess.run(
        [str(uv), "lock", "--offline", "--no-index", "--find-links", ".", "--python", "3.12"],
        cwd=root,
        check=True,
    )
    document = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    print(json.dumps(document), flush=True)
    graph = inspect_uv_lock(root, "app", "3.12", "x86_64", ["map"])
    print(json.dumps([item.model_dump() for item in graph.edges]), flush=True)
    normal = next(item for item in graph.edges if item.to_package == "helper")
    optional = next(item for item in graph.edges if item.to_package == "optional-helper")
    assert normal.selected_extra == optional.selected_extra == "map"
    assert normal.activated_dependency_extra is None
    assert optional.activated_dependency_extra == "feature"
    assert optional.marker == "sys_platform == 'win32'"


if __name__ == "__main__":
    main()
