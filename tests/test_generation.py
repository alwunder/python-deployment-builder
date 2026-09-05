from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.analysis.resources import resolve_package_data_members
from python_deployment_builder.cli import build_parser, main
from python_deployment_builder.generation.acquisition import (
    PreparationError,
    acquire_pinned_uv,
    extract_verified_uv,
    verify_uv_version,
)
from python_deployment_builder.generation.artifacts import (
    validate_application_wheel,
    validate_approved_wheel,
)
from python_deployment_builder.generation.cmd import parse_certutil_sha256
from python_deployment_builder.generation.generator import (
    _git_tracked_paths,
    _planned_generated_paths,
    _render_owned_files,
    _selected_deployment_paths,
    _staging_files,
    generate_deployment_kit,
)
from python_deployment_builder.generation.manifest import build_deployment_manifest
from python_deployment_builder.generation.preparation import (
    LockPreparationResult,
    prepare_lockfile,
)
from python_deployment_builder.generation.security import redact_secrets
from python_deployment_builder.generation.structural import validate_rendered_files
from python_deployment_builder.generation.templates import TEMPLATE_ROOT
from python_deployment_builder.models import (
    ApplicationArtifact,
    ApprovedArtifact,
    ArtifactAvailability,
    BootstrapArtifact,
    LockedDependency,
    LockGraphAssessment,
)
from python_deployment_builder.packaging.archive import safe_extract_zip
from python_deployment_builder.packaging.packager import package_deployment_kit
from python_deployment_builder.planning.index import target_marker_applies
from python_deployment_builder.planning.lockfile import inspect_uv_lock
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.validation.static import validate_static_kit

FIXTURES = Path(__file__).parent / "fixtures"


def _repository(name: str) -> MaterializedRepository:
    root = FIXTURES / name
    return MaterializedRepository(root=root, source=str(root), source_kind="local")


def _plan(name: str = "prepared_gui", extras: list[str] | None = None):
    repository = _repository(name)
    return create_deployment_plan(
        assess_repository(repository),
        selected_extras=extras or [],
        repository_root=repository.root,
    )


def _make_wheel(
    path: Path,
    name: str = "proxy-tools",
    version: str = "0.1.0",
    *,
    dist_info: str | None = None,
    requires_python: str | None = None,
    requires_python_values: list[str] | None = None,
    wheel_version: str = "1.0",
) -> Path:
    normalized = name.replace("-", "_")
    wheel = path / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = dist_info or f"{normalized}-{version}.dist-info"
    files = {
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            + "".join(
                f"Requires-Python: {value}\n"
                for value in (
                    requires_python_values
                    or ([requires_python] if requires_python else [])
                )
            )
            + "\n"
        ),
        f"{dist_info}/WHEEL": (
            f"Wheel-Version: {wheel_version}\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{normalized}/__init__.py": "VALUE = 1\n",
    }
    record_name = f"{dist_info}/RECORD"
    files[record_name] = _record_contents(files, record_name)
    with zipfile.ZipFile(wheel, "w") as bundle:
        for filename, data in files.items():
            bundle.writestr(filename, data)
    return wheel


def _make_application_wheel(
    path: Path,
    *,
    name: str = "mapped-app",
    version: str = "1.2.3",
    package: str = "installed_app",
    target: str = "installed_app.main:main",
    entry_group: str = "gui_scripts",
    entry_name: str = "mapped-app",
    include_cache: bool = False,
    requires_python: str | None = None,
    requires_python_values: list[str] | None = None,
    requires_dist_values: list[str] | None = None,
    wheel_version: str = "1.0",
    dist_info: str | None = None,
) -> Path:
    normalized = name.replace("-", "_")
    wheel = path / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = dist_info or f"{normalized}-{version}.dist-info"
    files = {
        f"{package}/__init__.py": "",
        f"{package}/main.py": "def main(): return 0\n",
        f"{package}/view.html": "<html></html>\n",
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            + "".join(
                f"Requires-Python: {value}\n"
                for value in (
                    requires_python_values
                    or ([requires_python] if requires_python else [])
                )
            )
            + "".join(f"Requires-Dist: {value}\n" for value in requires_dist_values or [])
            + "\n"
        ),
        f"{dist_info}/WHEEL": (
            f"Wheel-Version: {wheel_version}\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": f"[{entry_group}]\n{entry_name} = {target}\n",
    }
    if include_cache:
        files[f"{package}/__pycache__ (1)/main.pyc"] = "cache"
    record_name = f"{dist_info}/RECORD"
    files[record_name] = _record_contents(files, record_name)
    with zipfile.ZipFile(wheel, "w") as bundle:
        for filename, data in files.items():
            bundle.writestr(filename, data)
    return wheel


def _rewrite_application_wheel(
    wheel: Path,
    *,
    replacements: dict[str, str | bytes] | None = None,
    removals: set[str] | None = None,
    additions: dict[str, str | bytes] | None = None,
    recorded_paths: list[str] | None = None,
    recalculate_record: bool = True,
    record_contents: str | bytes | None = None,
) -> Path:
    with zipfile.ZipFile(wheel) as bundle:
        files = {
            item.filename: bundle.read(item)
            for item in bundle.infolist()
            if not item.filename.endswith(".dist-info/RECORD")
        }
        record_name = next(
            item.filename
            for item in bundle.infolist()
            if item.filename.endswith(".dist-info/RECORD")
        )
        existing_record = bundle.read(record_name)
    for name in removals or set():
        files.pop(name, None)
    for name, data in {**(replacements or {}), **(additions or {})}.items():
        files[name] = data.encode() if isinstance(data, str) else data
    if record_contents is not None:
        files[record_name] = (
            record_contents.encode() if isinstance(record_contents, str) else record_contents
        )
    elif recalculate_record:
        paths = list(files) if recorded_paths is None else recorded_paths
        files[record_name] = _record_contents(files, record_name, paths).encode()
    else:
        files[record_name] = existing_record
    with zipfile.ZipFile(wheel, "w") as bundle:
        for filename, data in files.items():
            bundle.writestr(filename, data)
    return wheel


def _record_contents(
    files: dict[str, str | bytes], record_name: str, paths: list[str] | None = None
) -> str:
    """Create a Wheel-compliant RECORD for the supplied in-memory members."""

    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for filename in paths or files:
        data = files.get(filename)
        if data is None:
            writer.writerow((filename, "", ""))
            continue
        data_bytes = data.encode() if isinstance(data, str) else data
        digest = base64.urlsafe_b64encode(hashlib.sha256(data_bytes).digest()).rstrip(b"=")
        writer.writerow((filename, f"sha256={digest.decode()}", str(len(data_bytes))))
    writer.writerow((record_name, "", ""))
    return output.getvalue()


def _record_with_member_values(
    wheel: Path, member_name: str, *, digest: str | None = None, size: str | None = None
) -> str:
    """Return RECORD content with one ordinary member's integrity values replaced."""

    with zipfile.ZipFile(wheel) as bundle:
        record_name = next(
            item.filename
            for item in bundle.infolist()
            if item.filename.endswith(".dist-info/RECORD")
        )
        rows = list(csv.reader(io.StringIO(bundle.read(record_name).decode("utf-8"))))
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for row in rows:
        if row[0] == member_name:
            row[1] = row[1] if digest is None else digest
            row[2] = row[2] if size is None else size
        writer.writerow(row)
    return output.getvalue()


def _write_mapped_project(
    root: Path,
    *,
    version: str = "1.2.3",
    entry_group: str = "gui-scripts",
    entry_name: str = "mapped-app",
    target: str = "installed_app.main:main",
) -> None:
    (root / "code").mkdir()
    (root / "code/__init__.py").write_text("", encoding="utf-8")
    (root / "code/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (root / "code/view.html").write_text("<html></html>\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f"""[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"
[project]
name = "mapped-app"
version = "{version}"
requires-python = ">=3.12"
dependencies = []
[project.{entry_group}]
{entry_name} = "{target}"
[tool.setuptools]
packages = ["installed_app"]
package-dir = {{installed_app = "code"}}
[tool.setuptools.package-data]
installed_app = ["view.html"]
""",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        """version = 1
revision = 3
requires-python = ">=3.12"
[[package]]
name = "mapped-app"
version = "1.2.3"
source = { virtual = "." }
""",
        encoding="utf-8",
    )


def _application_plan_with_locked_dependencies(
    plan,
    dependencies: list[tuple[str, str]],
    *,
    extras: list[str] | None = None,
):
    configured = plan.model_copy(deep=True)
    configured.lock_graph = LockGraphAssessment(
        inspected=True,
        python_version=configured.runtime.python_version,
        architecture=configured.runtime.architecture,
        selected_extras=extras or [],
        dependencies=[
            LockedDependency(
                name=name,
                version=version,
                direct=True,
                artifact=ArtifactAvailability(
                    compatible_wheel_available=True,
                    source_distribution_available=False,
                    policy="wheel_usable",
                ),
            )
            for name, version in dependencies
        ],
    )
    return configured


def _write_requests_lock(root: Path, *, version: str = "2.31.0") -> bytes:
    """Write a minimal inspected uv lock graph for mapped-app -> requests."""

    content = (
        f'''version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "mapped-app"
version = "1.2.3"
source = {{ virtual = "." }}
dependencies = [{{ name = "requests" }}]

[[package]]
name = "requests"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://example.invalid/requests-{version}-py3-none-any.whl" }}]
'''.encode()
    )
    (root / "uv.lock").write_bytes(content)
    return content


def _write_dependency_extra_lock(
    root: Path,
    *,
    requested_extras: list[str] | None = None,
    include_bar_helper: bool = True,
    include_baz_helper: bool = True,
    include_transitive_helper: bool = True,
    bar_marker: str | None = None,
) -> None:
    """Write uv's edge ``extra`` and optional-dependency representation for foo extras."""

    requested = ", ".join(f'"{item}"' for item in requested_extras or [])
    marker = f', marker = "{bar_marker.replace(chr(34), chr(92) + chr(34))}"' if bar_marker else ""
    parts = [
        '[[package]]\nname = "mapped-app"\nversion = "1.2.3"\n'
        'source = { virtual = "." }\n'
        f'dependencies = [{{ name = "foo", extra = [{requested}] }}]\n',
        '[[package]]\nname = "foo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'dependencies = [{ name = "base-helper" }]\n'
        'wheels = [{ url = "https://example.invalid/foo-1.0-py3-none-any.whl" }]\n'
        '\n[package.optional-dependencies]\n'
        f'bar = [{{ name = "bar-helper"{marker} }}]\n'
        'baz = [{ name = "baz-helper" }]\n',
        '[[package]]\nname = "base-helper"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'wheels = [{ url = "https://example.invalid/base_helper-1.0-py3-none-any.whl" }]\n',
    ]
    if include_bar_helper:
        parts.append(
            '[[package]]\nname = "bar-helper"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'dependencies = [{ name = "transitive-helper" }]\n'
            'wheels = [{ url = "https://example.invalid/bar_helper-1.0-py3-none-any.whl" }]\n'
        )
    if include_baz_helper:
        parts.append(
            '[[package]]\nname = "baz-helper"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'wheels = [{ url = "https://example.invalid/baz_helper-1.0-py3-none-any.whl" }]\n'
        )
    if include_transitive_helper:
        parts.append(
            '[[package]]\nname = "transitive-helper"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'wheels = [{ url = '
            '"https://example.invalid/transitive_helper-1.0-py3-none-any.whl" }]\n'
        )
    (root / "uv.lock").write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n\n' + "\n".join(parts),
        encoding="utf-8",
    )


def _plan_with_dependency_extra_lock(source: Path, *, selected_extras: list[str] | None = None):
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    graph = inspect_uv_lock(
        source,
        "mapped-app",
        plan.runtime.python_version,
        plan.runtime.architecture,
        selected_extras or [],
    )
    return assessment, plan.model_copy(
        update={"lock_graph": graph.model_copy(update={"selected_extras": selected_extras or []})}
    )


def _load_template_module(name: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(TEMPLATE_ROOT))
    spec = importlib.util.spec_from_file_location(f"generated_{name}", TEMPLATE_ROOT / name)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_cli_parses_repeatable_inputs() -> None:
    arguments = build_parser().parse_args(
        [
            "generate",
            "repo",
            "--extra",
            "map",
            "--extra",
            "reports",
            "--artifact",
            r"proxy-tools=C:\wheels\proxy.whl",
            "--application-wheel",
            r"C:\wheels\application.whl",
            "--bootstrap",
            "online_cmd",
            "--system-certs",
            "--prepare-lock",
            "--dry-run",
        ]
    )
    assert arguments.extra == ["map", "reports"]
    assert arguments.bootstrap == "online_cmd"
    assert arguments.application_wheel == Path(r"C:\wheels\application.whl")
    assert arguments.system_certs and arguments.prepare_lock and arguments.dry_run


def test_application_wheel_validation_and_package_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "Run Legacy.bat").write_text("legacy deployment", encoding="utf-8")
    (source / "tests").mkdir()
    (source / "tests/test_app.py").write_text("pass\n", encoding="utf-8")
    cache = source / "code/__pycache__ (1)"
    cache.mkdir()
    (cache / "main.pyc").write_bytes(b"cache")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path)

    artifact, resolved = validate_application_wheel(wheel, assessment, plan)

    assert resolved == wheel.resolve()
    assert artifact.distribution_name == "mapped-app"
    assert artifact.version == "1.2.3"
    assert artifact.entry_point_target == "installed_app.main:main"
    assert plan.deployment_mode == "package"
    assert _staging_files(source, assessment, plan, include=True).keys() == {
        "pyproject.toml",
        "uv.lock",
    }

    fake_uv = tmp_path / "developer-uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    output = tmp_path / "kit"
    result = generate_deployment_kit(repository, output, application_wheel=wheel)

    assert result.manifest.deployment_mode == "package"
    assert result.manifest.source_roots == []
    assert result.manifest.application_artifact.sha256 == artifact.sha256
    assert (output / "deployment/application" / wheel.name).is_file()
    assert not (output / "code").exists()
    assert not (output / "Run Legacy.bat").exists()
    assert not (output / "tests").exists()
    assert not list(output.rglob("*.pyc"))


def test_application_wheel_uses_declared_group_not_launch_kind(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source, entry_group="scripts", entry_name="gui-tool")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)

    assert plan.entry_point is not None
    assert (plan.entry_point.declared_group, plan.entry_point.kind) == (
        "console_scripts",
        "gui",
    )
    valid = _make_application_wheel(
        tmp_path,
        entry_group="console_scripts",
        entry_name="gui-tool",
    )
    validate_application_wheel(valid, assessment, plan)

    valid.unlink()
    wrong_group = _make_application_wheel(
        tmp_path,
        entry_group="gui_scripts",
        entry_name="gui-tool",
    )
    with pytest.raises(PreparationError, match="entry point disagrees"):
        validate_application_wheel(wrong_group, assessment, plan)

    plan.entry_point.declared_group = "unknown"
    with pytest.raises(PreparationError, match="will not infer"):
        validate_application_wheel(wrong_group, assessment, plan)


def test_gui_scripts_wheel_must_match_gui_declared_group(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    assert plan.entry_point is not None
    assert (plan.entry_point.declared_group, plan.entry_point.kind) == ("gui_scripts", "gui")

    valid = _make_application_wheel(tmp_path)
    validate_application_wheel(valid, assessment, plan)
    valid.unlink()
    wrong_group = _make_application_wheel(tmp_path, entry_group="console_scripts")
    with pytest.raises(PreparationError, match="entry point disagrees"):
        validate_application_wheel(wrong_group, assessment, plan)


def test_poetry_string_script_uses_console_scripts_for_wheel_validation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "code").mkdir()
    (source / "code/__init__.py").write_text("", encoding="utf-8")
    (source / "code/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
[tool.poetry]
name = "mapped-app"
version = "1.2.3"
[tool.poetry.scripts]
poetry-tool = "installed_app.main:main"
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    assert plan.entry_point is not None
    assert plan.deployment_mode == "package"
    assert plan.entry_point.declared_group == "console_scripts"

    wheel = _make_application_wheel(
        tmp_path,
        entry_group="console_scripts",
        entry_name="poetry-tool",
    )
    validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_rejects_wrong_target_and_runtime_cache(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)

    wrong_target = _make_application_wheel(tmp_path, target="installed_app.other:main")
    with pytest.raises(PreparationError, match="entry point disagrees"):
        validate_application_wheel(wrong_target, assessment, plan)
    wrong_target.unlink()
    cached = _make_application_wheel(tmp_path, include_cache=True)
    with pytest.raises(PreparationError, match="runtime cache"):
        validate_application_wheel(cached, assessment, plan)


@pytest.mark.parametrize("wheel_version", ["1.0", "1.1"])
def test_supported_wheel_major_one_versions_pass(
    tmp_path: Path, wheel_version: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)

    validate_application_wheel(
        _make_application_wheel(tmp_path, wheel_version=wheel_version), assessment, plan
    )


@pytest.mark.parametrize("wheel_version", ["2.0", "broken"])
def test_unsupported_or_malformed_wheel_version_rejects_application_wheel(
    tmp_path: Path, wheel_version: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)
    message = "Unsupported Wheel-Version" if wheel_version == "2.0" else "Malformed WHEEL"

    with pytest.raises(PreparationError, match=message):
        validate_application_wheel(
            _make_application_wheel(tmp_path, wheel_version=wheel_version), assessment, plan
        )


def test_unsupported_wheel_version_rejects_approved_dependency_wheel(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])

    with pytest.raises(PreparationError, match="Unsupported Wheel-Version"):
        validate_approved_wheel(
            f"proxy-tools={_make_wheel(tmp_path, wheel_version='2.0')}", plan
        )


@pytest.mark.parametrize(
    ("dist_info", "accepted"),
    [
        ("mapped_app-1.2.3.dist-info", True),
        ("Mapped_App-1.2.3.dist-info", True),
        ("wrong_name-1.2.3.dist-info", False),
        ("mapped_app-2.0.dist-info", False),
        ("wrong_name-2.0.dist-info", False),
        ("mapped_app-not-a-version.dist-info", False),
    ],
)
def test_application_wheel_dist_info_identity_matches_filename(
    tmp_path: Path, dist_info: str, accepted: bool
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path, dist_info=dist_info)

    if accepted:
        assert validate_application_wheel(wheel, assessment, plan)[0].filename == wheel.name
    else:
        with pytest.raises(PreparationError, match="directory identity"):
            validate_application_wheel(wheel, assessment, plan)


def test_dist_info_namespace_and_data_identity_are_checked_before_record(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)

    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={
            "mapped_app-1.2.3.dist-info/licenses/LICENSE": "license\n",
            "mapped_app-1.2.3.dist-info/sboms/source.json": "{}\n",
            "other-1.0.dist-info/licenses/LICENSE": "other license\n",
        },
    )
    with pytest.raises(PreparationError, match="exactly one distribution dist-info"):
        validate_application_wheel(wheel, assessment, plan)

    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"wrong_name-1.2.3.data/purelib/unused.txt": "unused\n"},
    )
    with pytest.raises(PreparationError, match=".data directory identity"):
        validate_application_wheel(wheel, assessment, plan)

    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={
            "mapped_app-1.2.3.dist-info/licenses/LICENSE": "license\n",
            "mapped_app-1.2.3.dist-info/sboms/source.json": "{}\n",
            "mapped_app-1.2.3.data/purelib/unused.txt": "unused\n",
        },
    )
    assert validate_application_wheel(wheel, assessment, plan)[0].filename == wheel.name


def test_approved_wheel_uses_shared_dist_info_identity_validation(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])
    wrong = _make_wheel(tmp_path, dist_info="wrong_name-0.1.0.dist-info")

    with pytest.raises(PreparationError, match="directory identity"):
        validate_approved_wheel(f"proxy-tools={wrong}", plan)

    historical = _make_wheel(tmp_path, dist_info="Proxy_Tools-0.1.0.dist-info")
    assert validate_approved_wheel(f"proxy-tools={historical}", plan)[0].filename == historical.name


@pytest.mark.parametrize(
    ("requires_dist", "locked", "error"),
    [
        ([], [], None),
        (["requests>=2"], [("Requests", "2.31.0")], None),
        (["requests>=99"], [("requests", "2.31.0")], "incompatible"),
        (["totally-new-package>=1"], [], "absent"),
        (["windows-only>=1; sys_platform == 'win32'"], [("windows-only", "1.0")], None),
        (["linux-only>=1; sys_platform == 'linux'"], [], None),
        (["future-only>=1; python_version >= '3.13'"], [], None),
    ],
)
def test_application_wheel_requires_dist_uses_selected_locked_target_environment(
    tmp_path: Path,
    requires_dist: list[str],
    locked: list[tuple[str, str]],
    error: str | None,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, repository_root=source), locked
    )
    wheel = _make_application_wheel(tmp_path, requires_dist_values=requires_dist)

    if error is None:
        validate_application_wheel(wheel, assessment, plan)
    else:
        with pytest.raises(PreparationError, match=error):
            validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_requires_dist_selected_extra_controls_marker(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    base_plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(
        tmp_path,
        requires_dist_values=["pywebview>=6; extra == 'map'"],
    )

    validate_application_wheel(
        wheel,
        assessment,
        _application_plan_with_locked_dependencies(base_plan, []),
    )
    validate_application_wheel(
        wheel,
        assessment,
        _application_plan_with_locked_dependencies(
            base_plan, [("pywebview", "6.0")], extras=["map"]
        ),
    )
    with pytest.raises(PreparationError, match="absent"):
        validate_application_wheel(
            wheel,
            assessment,
            _application_plan_with_locked_dependencies(base_plan, [], extras=["map"]),
        )


@pytest.mark.parametrize("selected_extra", ["feature_one", "feature-one", "feature.one"])
def test_application_wheel_extra_marker_normalizes_selected_extra_identity(
    tmp_path: Path, selected_extra: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, repository_root=source),
        [("helper", "1.0")],
        extras=[selected_extra],
    )

    validate_application_wheel(
        _make_application_wheel(
            tmp_path, requires_dist_values=['helper>=1; extra == "feature_one"']
        ),
        assessment,
        plan,
    )


@pytest.mark.parametrize(
    ("requires_dist", "error"),
    [
        (["requests=>2"], "malformed Requires-Dist"),
        (["helper; implementation_version <"], "malformed Requires-Dist"),
        (["requests @ https://example.invalid/requests.whl"], "direct references"),
    ],
)
def test_application_wheel_requires_dist_rejects_unprovable_metadata(
    tmp_path: Path, requires_dist: list[str], error: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, repository_root=source), [("requests", "2.31.0")]
    )
    wheel = _make_application_wheel(tmp_path, requires_dist_values=requires_dist)

    with pytest.raises(PreparationError, match=error):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("marker", "error"),
    [
        ('python_version < "3.13"', "absent"),
        ('implementation_version < "3.13"', "cannot be proven"),
        ('platform_python_implementation == "CPython"', "absent"),
        ('implementation_name == "cpython"', "absent"),
        ('sys_platform == "win32"', "absent"),
        ('os_name == "nt"', "absent"),
        ('platform_system == "Windows"', "absent"),
        ('platform_machine == "AMD64"', "absent"),
    ],
)
def test_application_wheel_markers_use_complete_target_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, marker: str, error: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, repository_root=source), []
    )
    monkeypatch.setattr(
        "packaging.markers.default_environment",
        lambda: {"implementation_version": "3.13.0", "sys_platform": "linux"},
    )
    wheel = _make_application_wheel(
        tmp_path, requires_dist_values=[f"helper; {marker}"]
    )

    with pytest.raises(PreparationError, match=error):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    "marker",
    [
        'python_full_version >= "3.12.1"',
        'implementation_version >= "3.12.1"',
    ],
)
def test_application_wheel_patch_sensitive_marker_is_not_proven_for_minor_target(
    tmp_path: Path, marker: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, repository_root=source), []
    )

    with pytest.raises(PreparationError, match="patch-sensitive"):
        validate_application_wheel(
            _make_application_wheel(
                tmp_path, requires_dist_values=[f"helper; {marker}"]
            ),
            assessment,
            plan,
        )


def test_application_wheel_target_marker_arm64_and_unprovable_field_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    arm_plan = _application_plan_with_locked_dependencies(
        create_deployment_plan(assessment, architecture="arm64", repository_root=source), []
    )
    assert target_marker_applies('platform_machine == "ARM64"', "3.12", "arm64")
    assert not target_marker_applies('platform_machine == "AMD64"', "3.12", "arm64")
    arm_wheel = _make_application_wheel(
        tmp_path, requires_dist_values=['helper; platform_machine == "ARM64"']
    )
    with pytest.raises(PreparationError, match="absent"):
        validate_application_wheel(arm_wheel, assessment, arm_plan)

    with pytest.raises(PreparationError, match="cannot be proven"):
        validate_application_wheel(
            _make_application_wheel(
                tmp_path,
                requires_dist_values=['helper; platform_release == "10"'],
            ),
            assessment,
            _application_plan_with_locked_dependencies(
                create_deployment_plan(assessment, repository_root=source), []
            ),
        )


def test_application_wheel_dependency_requested_extra_closure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)

    _write_dependency_extra_lock(source, requested_extras=["bar"])
    assessment, plan = _plan_with_dependency_extra_lock(source)
    foo = next(item for item in plan.lock_graph.dependencies if item.name == "foo")
    root_edge = next(
        item
        for item in plan.lock_graph.edges
        if item.from_package == "mapped-app" and item.to_package == "foo"
    )
    assert foo.requested_dependency_extras == ["bar"]
    assert foo.available_dependency_extras == ["bar", "baz"]
    assert root_edge.requested_dependency_extras == ["bar"]
    validate_application_wheel(
        _make_application_wheel(tmp_path, requires_dist_values=["Foo[bar]>=1"]),
        assessment,
        plan,
    )

    _write_dependency_extra_lock(source, requested_extras=["bar"], include_bar_helper=False)
    assessment, incomplete = _plan_with_dependency_extra_lock(source)
    with pytest.raises(PreparationError, match="closure is incomplete"):
        validate_application_wheel(
            _make_application_wheel(tmp_path, requires_dist_values=["foo[bar]>=1"]),
            assessment,
            incomplete,
        )


def test_application_wheel_dependency_requested_extra_variants_and_markers(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)

    _write_dependency_extra_lock(source, requested_extras=["bar", "baz"])
    assessment, complete = _plan_with_dependency_extra_lock(source)
    validate_application_wheel(
        _make_application_wheel(tmp_path, requires_dist_values=["foo[bar,baz]>=1"]),
        assessment,
        complete,
    )

    _write_dependency_extra_lock(source, requested_extras=[] , include_bar_helper=False)
    assessment, base_only = _plan_with_dependency_extra_lock(source)
    validate_application_wheel(
        _make_application_wheel(tmp_path, requires_dist_values=["foo>=1"]),
        assessment,
        base_only,
    )
    validate_application_wheel(
        _make_application_wheel(
            tmp_path, requires_dist_values=['foo[bar]>=1; extra == "map"']
        ),
        assessment,
        base_only,
    )

    _write_dependency_extra_lock(
        source,
        requested_extras=["bar"],
        include_bar_helper=False,
        bar_marker='implementation_version < "3.13"',
    )
    assessment, selected_map = _plan_with_dependency_extra_lock(source, selected_extras=["map"])
    with pytest.raises(PreparationError, match="closure is incomplete"):
        validate_application_wheel(
            _make_application_wheel(
                tmp_path, requires_dist_values=['foo[bar]>=1; extra == "map"']
            ),
            assessment,
            selected_map,
        )

    _write_dependency_extra_lock(
        source, requested_extras=["bar"], include_transitive_helper=False
    )
    assessment, transitive_incomplete = _plan_with_dependency_extra_lock(source)
    with pytest.raises(PreparationError, match="closure is incomplete"):
        validate_application_wheel(
            _make_application_wheel(tmp_path, requires_dist_values=["foo[bar]>=1"]),
            assessment,
            transitive_incomplete,
        )


def test_package_prepare_lock_reassesses_before_requires_dist_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "uv.lock").unlink()
    pyproject = source / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            "dependencies = []", 'dependencies = ["requests>=2"]'
        ),
        encoding="utf-8",
    )
    wheel = _make_application_wheel(tmp_path, requires_dist_values=["requests>=2"])
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )

    def prepare(root: Path, *args, **kwargs) -> LockPreparationResult:
        assert not (root / "uv.lock").exists()
        _write_requests_lock(root)
        return LockPreparationResult(
            path=root / "uv.lock", created=True, checked=True, commands=()
        )

    monkeypatch.setattr("python_deployment_builder.generation.generator.prepare_lockfile", prepare)
    result = generate_deployment_kit(
        repository,
        tmp_path / "kit",
        application_wheel=wheel,
        prepare_lock=True,
        bootstrap_mode="online_cmd",
    )

    assert result.generated
    assert (tmp_path / "kit/uv.lock").read_bytes() == (source / "uv.lock").read_bytes()


def test_package_wheel_requires_dist_without_prepare_lock_reports_lock_blocker(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "uv.lock").unlink()
    wheel = _make_application_wheel(tmp_path, requires_dist_values=["requests>=2"])
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")

    with pytest.raises(PreparationError, match="uv.lock is missing"):
        generate_deployment_kit(repository, tmp_path / "kit", application_wheel=wheel)
    assert not (tmp_path / "kit").exists()


@pytest.mark.parametrize("git_backed", [False, True])
def test_missing_lock_dry_run_is_previewable_without_staging_or_provenance_mutation(
    tmp_path: Path, git_backed: bool
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURES / "prepared_gui", source, ignore=shutil.ignore_patterns("__pycache__"))
    (source / "uv.lock").unlink()
    if git_backed:
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "kit"

    result = generate_deployment_kit(repository, output, dry_run=True, bootstrap_mode="online_cmd")

    assert result.dry_run and not result.generated
    assert any("--prepare-lock" in action for action in result.preview.developer_actions)
    assert not (source / "uv.lock").exists()
    assert not output.exists()
    if git_backed:
        status = subprocess.run(
            ["git", "-C", str(source), "status", "--short"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert status.stdout == ""

    with pytest.raises(PreparationError, match="uv.lock is missing"):
        generate_deployment_kit(repository, output, bootstrap_mode="online_cmd")


def test_package_missing_lock_dry_run_validates_structure_but_defers_requires_dist(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "uv.lock").unlink()
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    wheel = _make_application_wheel(tmp_path, requires_dist_values=["requests>=99"])

    preview = generate_deployment_kit(
        repository,
        tmp_path / "kit",
        application_wheel=wheel,
        dry_run=True,
        bootstrap_mode="online_cmd",
    )
    assert preview.preview.application_artifact is not None
    assert not (source / "uv.lock").exists()
    with pytest.raises(PreparationError, match="entry point disagrees"):
        generate_deployment_kit(
            repository,
            tmp_path / "kit",
            application_wheel=_make_application_wheel(
                tmp_path, target="installed_app.other:main"
            ),
            dry_run=True,
            bootstrap_mode="online_cmd",
        )


def test_package_prepare_lock_rejects_final_incompatible_requires_dist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "uv.lock").unlink()
    wheel = _make_application_wheel(tmp_path, requires_dist_values=["requests>=99"])
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: (
            _write_requests_lock(root),
            LockPreparationResult(path=root / "uv.lock", created=True, checked=True, commands=()),
        )[1],
    )

    with pytest.raises(PreparationError, match="incompatible"):
        generate_deployment_kit(
            repository,
            tmp_path / "kit",
            application_wheel=wheel,
            prepare_lock=True,
            bootstrap_mode="online_cmd",
        )
    assert (source / "uv.lock").is_file()
    assert not (tmp_path / "kit").exists()


@pytest.mark.parametrize(
    ("name", "version", "message"),
    [
        ("other-app", "1.2.3", "name mismatch"),
        ("mapped-app", "9.9", "version mismatch"),
    ],
)
def test_application_wheel_rejects_wrong_filename_identity(
    tmp_path: Path, name: str, version: str, message: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path, name=name, version=version)

    with pytest.raises(PreparationError, match=message):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("project_version", "wheel_version"),
    [("1.0-rc1", "1.0rc1"), ("1.0-1", "1.0.post1")],
)
def test_application_wheel_accepts_equivalent_pep440_version_spellings(
    tmp_path: Path, project_version: str, wheel_version: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source, version=project_version)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path, version=wheel_version)

    artifact, _ = validate_application_wheel(wheel, assessment, plan)

    assert artifact.version == project_version


def test_application_wheel_rejects_invalid_authoritative_and_metadata_versions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path)

    assessment.project.version = "invalid version!"
    with pytest.raises(PreparationError, match="authoritative project version is invalid"):
        validate_application_wheel(wheel, assessment, plan)

    assessment.project.version = "1.2.3"
    _rewrite_application_wheel(
        wheel,
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: mapped-app\nVersion: invalid version!\n\n"
            )
        },
    )
    with pytest.raises(PreparationError, match="METADATA version is invalid"):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize("member", ["../escape.py", "/absolute.py", "C:/absolute.py"])
def test_application_wheel_rejects_unsafe_archive_members(
    tmp_path: Path, member: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path), additions={member: "unsafe"}
    )

    with pytest.raises(PreparationError, match="unsafe member"):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_rejects_duplicate_and_case_conflicting_paths(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path)
    with zipfile.ZipFile(wheel, "a") as bundle:
        bundle.writestr("INSTALLED_APP/main.py", "conflict")

    with pytest.raises(PreparationError, match="duplicate or conflicting"):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("metadata_name", "content", "message"),
    [
        (
            "mapped_app-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: other-app\nVersion: 1.2.3\n\n",
            "distribution name",
        ),
        (
            "mapped_app-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: mapped-app\nVersion: 9.9\n\n",
            "version",
        ),
        ("mapped_app-1.2.3.dist-info/METADATA", "not metadata\n", "Malformed METADATA"),
        ("mapped_app-1.2.3.dist-info/WHEEL", "not wheel metadata\n", "Malformed WHEEL"),
    ],
)
def test_application_wheel_rejects_metadata_disagreement_and_malformed_metadata(
    tmp_path: Path, metadata_name: str, content: str, message: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path), replacements={metadata_name: content}
    )

    with pytest.raises(PreparationError, match=message):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_record_is_an_exact_file_inventory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)

    wheel = _make_application_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as bundle:
        recorded = [
            item.filename
            for item in bundle.infolist()
            if not item.filename.endswith(".dist-info/RECORD")
        ]
    _rewrite_application_wheel(wheel, recorded_paths=[*recorded, "ghost.py"])
    with pytest.raises(PreparationError, match="nonexistent"):
        validate_application_wheel(wheel, assessment, plan)

    wheel.unlink()
    wheel = _make_application_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as bundle:
        recorded = [
            item.filename
            for item in bundle.infolist()
            if not item.filename.endswith(".dist-info/RECORD")
        ]
    _rewrite_application_wheel(
        wheel,
        additions={"installed_app/unrecorded.txt": "unexpected"},
        recorded_paths=recorded,
    )
    with pytest.raises(PreparationError, match="incomplete"):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("wheel_kind", "member_name"),
    [
        ("application", "installed_app/main.py"),
        ("approved", "proxy_tools/__init__.py"),
    ],
)
def test_wheel_record_rejects_stale_hash_and_size_for_all_wheel_contracts(
    tmp_path: Path, wheel_kind: str, member_name: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    application_plan = create_deployment_plan(assessment)
    approved_plan = _plan("optional_map_app", ["map"])
    wheel = (
        _make_application_wheel(tmp_path)
        if wheel_kind == "application"
        else _make_wheel(tmp_path)
    )

    stale_hash = _rewrite_application_wheel(
        wheel,
        replacements={
            member_name: "def main(): return 1\n" if wheel_kind == "application" else "VALUE = 2\n"
        },
        recalculate_record=False,
    )
    with pytest.raises(PreparationError, match="RECORD hash mismatch"):
        if wheel_kind == "application":
            validate_application_wheel(stale_hash, assessment, application_plan)
        else:
            validate_approved_wheel(f"proxy-tools={stale_hash}", approved_plan)

    wheel.unlink()
    wheel = (
        _make_application_wheel(tmp_path)
        if wheel_kind == "application"
        else _make_wheel(tmp_path)
    )
    stale_size = _rewrite_application_wheel(
        wheel,
        replacements={
            member_name: "def main(): return 100\n" if wheel_kind == "application" else "longer"
        },
        recalculate_record=False,
    )
    with pytest.raises(PreparationError, match="RECORD size mismatch"):
        if wheel_kind == "application":
            validate_application_wheel(stale_size, assessment, application_plan)
        else:
            validate_approved_wheel(f"proxy-tools={stale_size}", approved_plan)


@pytest.mark.parametrize(
    ("digest", "size", "message"),
    [
        ("not-a-digest", None, "invalid hash"),
        ("sha256=!!!", None, "invalid hash"),
        ("md5=abcd", None, "invalid hash"),
        ("", None, "invalid hash"),
        (None, "not-a-size", "invalid size"),
        (None, "", "invalid size"),
    ],
)
def test_application_wheel_rejects_malformed_record_integrity_values(
    tmp_path: Path, digest: str | None, size: str | None, message: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path)
    record = _record_with_member_values(
        wheel, "installed_app/main.py", digest=digest, size=size
    )
    _rewrite_application_wheel(wheel, record_contents=record)

    with pytest.raises(PreparationError, match=message):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("removals", "additions", "message"),
    [
        ({"installed_app/main.py"}, {}, "entry-point module"),
        ({"installed_app/view.html"}, {}, "package data"),
        (set(), {"installed_app/native.dll": b"native"}, "native binaries"),
        (set(), {"installed_app/module.pyo": b"cache"}, "runtime cache"),
    ],
)
def test_application_wheel_rejects_missing_runtime_content_and_binary_content(
    tmp_path: Path,
    removals: set[str],
    additions: dict[str, bytes],
    message: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path), removals=removals, additions=additions
    )

    with pytest.raises(PreparationError, match=message):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_requires_every_concrete_declared_package_data_member(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "code/data").mkdir()
    (source / "code/data/defaults.json").write_text("{}\n", encoding="utf-8")
    (source / "code/data/schema.json").write_text("{}\n", encoding="utf-8")
    pyproject = source / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'installed_app = ["view.html"]',
            'installed_app = ["view.html", "data/*.json"]',
        ),
        encoding="utf-8",
    )
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    only_one = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/data/defaults.json": "{}\n"},
    )

    with pytest.raises(PreparationError, match="installed_app/data/schema.json"):
        validate_application_wheel(only_one, assessment, plan)

    complete_directory = tmp_path / "complete"
    complete_directory.mkdir()
    complete = _rewrite_application_wheel(
        _make_application_wheel(complete_directory),
        additions={
            "installed_app/data/defaults.json": "{}\n",
            "installed_app/data/schema.json": "{}\n",
        },
    )
    artifact, _ = validate_application_wheel(complete, assessment, plan)

    assert artifact.filename == complete.name


def test_application_wheel_and_source_staging_honor_excluded_package_data(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "code/data").mkdir()
    (source / "code/data/defaults.json").write_text("{}\n", encoding="utf-8")
    (source / "code/data/private.json").write_text("{}\n", encoding="utf-8")
    pyproject = source / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'installed_app = ["view.html"]',
            'installed_app = ["view.html", "data/*.json"]\n'
            "[tool.setuptools.exclude-package-data]\n"
            'installed_app = ["data/private.json"]',
        ),
        encoding="utf-8",
    )
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    source_plan = plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"

    assert {
        (item.source_path, item.installed_member_path)
        for item in resolve_package_data_members(source, assessment.project)
    } == {
        ("code/data/defaults.json", "installed_app/data/defaults.json"),
        ("code/view.html", "installed_app/view.html"),
    }
    staged = _staging_files(source, assessment, source_plan, include=True)
    assert "code/data/defaults.json" in staged
    assert "code/data/private.json" not in staged

    defaults_only = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/data/defaults.json": "{}\n"},
    )
    assert validate_application_wheel(
        defaults_only, assessment, plan, repository_root=source
    )[0].filename == defaults_only.name

    missing_directory = tmp_path / "missing-default"
    missing_directory.mkdir()
    with pytest.raises(PreparationError, match="installed_app/data/defaults.json"):
        validate_application_wheel(
            _make_application_wheel(missing_directory),
            assessment,
            plan,
            repository_root=source,
        )

    private_directory = tmp_path / "with-private"
    private_directory.mkdir()
    with_private = _rewrite_application_wheel(
        _make_application_wheel(private_directory),
        additions={
            "installed_app/data/defaults.json": "{}\n",
            "installed_app/data/private.json": "{}\n",
        },
    )
    assert validate_application_wheel(
        with_private, assessment, plan, repository_root=source
    )[0].filename == with_private.name


def test_application_wheel_requires_nested_package_data_from_parent_mapping(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "lib/sub/data").mkdir(parents=True)
    (source / "lib/__init__.py").write_text("", encoding="utf-8")
    (source / "lib/sub/__init__.py").write_text("", encoding="utf-8")
    (source / "lib/sub/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (source / "lib/sub/data/default.json").write_text("{}\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        "[project]\nname = 'mapped-app'\nversion = '1.2.3'\ndependencies = []\n"
        "[project.gui-scripts]\nmapped-app = 'app.sub.main:main'\n"
        "[tool.setuptools]\npackages = ['app', 'app.sub']\npackage-dir = {app = 'lib'}\n"
        "[tool.setuptools.package-data]\n'app.sub' = ['data/*.json']\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    incomplete = _rewrite_application_wheel(
        _make_application_wheel(tmp_path, package="app", target="app.sub.main:main"),
        additions={"app/sub/__init__.py": "", "app/sub/main.py": "def main(): return 0\n"},
    )

    assert [
        (item.source_path, item.installed_member_path)
        for item in resolve_package_data_members(source, assessment.project)
    ] == [("lib/sub/data/default.json", "app/sub/data/default.json")]
    with pytest.raises(PreparationError, match="app/sub/data/default.json"):
        validate_application_wheel(incomplete, assessment, plan, repository_root=source)

    complete = _rewrite_application_wheel(
        incomplete, additions={"app/sub/data/default.json": "{}\n"}
    )
    artifact, _path = validate_application_wheel(
        complete, assessment, plan, repository_root=source
    )

    assert artifact.filename == complete.name


def test_application_wheel_resolves_wildcard_package_data_against_known_package(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "code/data").mkdir()
    (source / "code/data/defaults.json").write_text("{}\n", encoding="utf-8")
    (source / "code/data/schema.json").write_text("{}\n", encoding="utf-8")
    pyproject = source / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'installed_app = ["view.html"]',
            "'*' = [\"view.html\", \"data/*.json\"]",
        ),
        encoding="utf-8",
    )
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/data/defaults.json": "{}\n"},
    )

    with pytest.raises(PreparationError, match="installed_app/data/schema.json"):
        validate_application_wheel(wheel, assessment, plan)


def test_discovered_package_wildcard_data_is_required_in_application_wheel(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "src/example_app/data").mkdir(parents=True)
    (source / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (source / "src/example_app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (source / "src/example_app/data/defaults.json").write_text("{}\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "example-app"
version = "1.0"
[project.scripts]
example-app = "example_app.main:main"
[tool.setuptools.packages.find]
where = ["src"]
namespaces = false
[tool.setuptools.package-data]
"*" = ["data/*.json"]
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)
    incomplete = _make_application_wheel(
        tmp_path,
        name="example-app",
        version="1.0",
        package="example_app",
        target="example_app.main:main",
        entry_group="console_scripts",
        entry_name="example-app",
    )

    assert assessment.project.packages == ["example_app"]
    with pytest.raises(PreparationError, match="example_app/data/defaults.json"):
        validate_application_wheel(incomplete, assessment, plan, repository_root=source)

    complete = _rewrite_application_wheel(
        incomplete, additions={"example_app/data/defaults.json": "{}\n"}
    )
    assert validate_application_wheel(complete, assessment, plan, repository_root=source)[0]


def test_default_discovered_python_surface_and_wildcard_data_are_required_in_wheel(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "src/example_app/data").mkdir(parents=True)
    (source / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (source / "src/example_app/main.py").write_text("from . import helpers\n", encoding="utf-8")
    (source / "src/example_app/helpers.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "src/example_app/data/defaults.json").write_text("{}\n", encoding="utf-8")
    (source / "src/helper.py").write_text("VALUE = 2\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[project]
name = "example-app"
version = "1.0"
[project.scripts]
example = "example_app.main:main"
[tool.setuptools.package-data]
"*" = ["data/*.json"]
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)
    incomplete = _make_application_wheel(
        tmp_path,
        name="example-app",
        version="1.0",
        package="example_app",
        target="example_app.main:main",
        entry_group="console_scripts",
        entry_name="example",
    )

    assert "example_app" in assessment.project.packages
    assert assessment.project.py_modules == ["helper"]
    with pytest.raises(PreparationError, match="example_app/data/defaults.json"):
        validate_application_wheel(incomplete, assessment, plan, repository_root=source)

    with pytest.raises(PreparationError, match="example_app/helpers.py"):
        validate_application_wheel(
            _rewrite_application_wheel(
                incomplete,
                additions={"example_app/data/defaults.json": "{}\n"},
            ),
            assessment,
            plan,
            repository_root=source,
        )

    with pytest.raises(PreparationError, match="helper.py"):
        validate_application_wheel(
            _rewrite_application_wheel(
                incomplete,
                additions={
                    "example_app/data/defaults.json": "{}\n",
                    "example_app/helpers.py": "VALUE = 1\n",
                },
            ),
            assessment,
            plan,
            repository_root=source,
        )

    complete = _rewrite_application_wheel(
        incomplete,
        additions={
            "example_app/data/defaults.json": "{}\n",
            "example_app/helpers.py": "VALUE = 1\n",
            "helper.py": "VALUE = 2\n",
        },
    )
    assert validate_application_wheel(complete, assessment, plan, repository_root=source)[0]


@pytest.mark.parametrize(
    ("py_modules", "missing_member"),
    [(False, "app/util.py"), (True, "helper.py")],
)
def test_application_wheel_requires_authoritative_python_source_surface(
    tmp_path: Path, py_modules: bool, missing_member: str
) -> None:
    source = tmp_path / "source"
    (source / "src/app").mkdir(parents=True)
    (source / "src/app/__init__.py").write_text("", encoding="utf-8")
    (source / "src/app/main.py").write_text(
        "from . import util\ndef main(): return util.VALUE\n", encoding="utf-8"
    )
    (source / "src/app/util.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "src/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    py_modules_text = "[tool.setuptools]\npy-modules = [\"helper\"]\n" if py_modules else ""
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "source-surface"
version = "1.0"
[project.scripts]
source-surface = "app.main:main"
"""
        + py_modules_text
        + """[tool.setuptools.packages.find]
where = ["src"]
namespaces = false
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(
        tmp_path,
        name="source-surface",
        version="1.0",
        package="app",
        target="app.main:main",
        entry_group="console_scripts",
        entry_name="source-surface",
    )

    with pytest.raises(PreparationError, match=missing_member):
        validate_application_wheel(wheel, assessment, plan, repository_root=source)

    complete = _rewrite_application_wheel(
        wheel,
        additions={
            "app/util.py": "VALUE = 1\n",
            **({"helper.py": "VALUE = 1\n"} if py_modules else {}),
        },
    )
    assert validate_application_wheel(complete, assessment, plan, repository_root=source)[0]


@pytest.mark.parametrize(
    ("requires_python", "accepted"),
    [
        (None, True),
        (">=3.11", True),
        (">=3.12,<3.13", True),
        ("==3.12.*", True),
        (">=3.9,!=3.9.0", True),
        (">=3.13", False),
        ("<3.12", False),
        (">=3.12.1", False),
        ("<3.12.1", False),
    ],
)
def test_application_wheel_requires_python_uses_selected_minor_policy(
    tmp_path: Path, requires_python: str | None, accepted: bool
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path, requires_python=requires_python)

    if accepted:
        assert validate_application_wheel(wheel, assessment, plan)[0].filename == wheel.name
    else:
        with pytest.raises(PreparationError, match="Requires-Python"):
            validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    "values",
    [[">=three"], [">=3.11", "<3.12"]],
)
def test_application_wheel_rejects_malformed_or_multiple_requires_python(
    tmp_path: Path, values: list[str]
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path, requires_python_values=values)

    with pytest.raises(PreparationError, match="Malformed Requires-Python"):
        validate_application_wheel(wheel, assessment, plan)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("installed_app/install.ps1", "Write-Host unsafe"),
        ("installed_app/tool.py", "COMMAND = 'powershell.exe -ExecutionPolicy bypass'"),
        ("installed_app/path.py", r"ROOT = 'C:\Users\developer\private'"),
        ("installed_app/.env", "API_KEY=secret"),
        ("installed_app/token.json", "{}"),
        ("installed_app/TOKEN.JSON", "{}"),
        ("mapped_app-1.2.3.dist-info/token.json", "{}"),
        ("installed_app/.pypirc", "[distutils]"),
        ("installed_app/pip.ini", "[global]"),
        ("installed_app/.env.production", "API_KEY=secret"),
        ("installed_app/.env.local", "API_KEY=secret"),
        ("installed_app/secret.py", "TOKEN = 'sk-abcdefghijklmnop'"),
        ("installed_app/settings.yaml", "api_key: sk-abcdefghijklmnop"),
        ("installed_app/settings.yml", "api_key: sk-abcdefghijklmnop"),
        ("installed_app/settings.toml", "api_key = 'sk-abcdefghijklmnop'"),
        ("installed_app/settings.ini", "api_key = sk-abcdefghijklmnop"),
        ("installed_app/settings.cfg", "api_key = sk-abcdefghijklmnop"),
        ("installed_app/token", "api_key = sk-abcdefghijklmnop"),
        ("installed_app/copy.py", "COMMAND = 'copy payload C:\\Program Files\\App'"),
    ],
)
def test_application_wheel_cannot_bypass_deployment_security_policy(
    tmp_path: Path, name: str, content: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path), additions={name: content}
    )

    with pytest.raises(PreparationError, match="security policy"):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_allows_environment_example_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/.env.example": "API_KEY=replace-me"},
    )

    artifact, _path = validate_application_wheel(wheel, assessment, plan)

    assert artifact.filename == wheel.name


def test_application_wheel_allows_non_secret_textual_configuration_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/settings.yaml": "theme: light\n"},
    )

    artifact, _path = validate_application_wheel(wheel, assessment, plan)

    assert artifact.filename == wheel.name


def test_application_wheel_extensionless_text_and_binary_resources_are_classified_safely(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    plan = create_deployment_plan(assessment)
    benign = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/scripts/tool": "#!/usr/bin/env python\nprint('ok')\n"},
    )
    assert validate_application_wheel(benign, assessment, plan)[0].filename == benign.name

    binary = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/blob": b"\x00\xffsk-abcdefghijklmnop"},
    )
    assert validate_application_wheel(binary, assessment, plan)[0].filename == binary.name


def test_application_wheel_rejects_obvious_secret_in_textual_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: mapped-app\nVersion: 1.2.3\n\n"
                "Project description: sk-abcdefghijklmnop\n"
            )
        },
    )

    with pytest.raises(PreparationError, match="security policy"):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_allows_non_secret_textual_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: mapped-app\nVersion: 1.2.3\n\n"
                "A normal project description.\n"
            )
        },
    )

    artifact, _path = validate_application_wheel(wheel, assessment, plan)

    assert artifact.filename == wheel.name


def test_application_wheel_rejects_configured_secret_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "code/main.py").write_text(
        "import os\nAPI_TOKEN = os.environ['APP_API_TOKEN']\ndef main(): return 0\n",
        encoding="utf-8",
    )
    secret = "configured-value-that-must-not-ship"
    monkeypatch.setenv("APP_API_TOKEN", secret)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        additions={"installed_app/config.py": f"TOKEN = {secret!r}"},
    )

    with pytest.raises(PreparationError, match="security policy"):
        validate_application_wheel(wheel, assessment, plan)


def test_application_wheel_rejects_configured_secret_in_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    (source / "code/main.py").write_text(
        "import os\nAPI_TOKEN = os.environ['APP_API_TOKEN']\ndef main(): return 0\n",
        encoding="utf-8",
    )
    secret = "configured-value-that-must-not-ship"
    monkeypatch.setenv("APP_API_TOKEN", secret)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _rewrite_application_wheel(
        _make_application_wheel(tmp_path),
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: mapped-app\nVersion: 1.2.3\n\n"
                f"Operational notes: {secret}\n"
            )
        },
    )

    with pytest.raises(PreparationError, match="security policy") as caught:
        validate_application_wheel(wheel, assessment, plan)

    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    "filename",
    [
        "mapped_app-1.2.3-cp313-cp313-win_amd64.whl",
        "mapped_app-1.2.3-cp312-cp312-win_arm64.whl",
    ],
)
def test_application_wheel_rejects_incompatible_python_and_platform_tags(
    tmp_path: Path, filename: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment)
    wheel = _make_application_wheel(tmp_path)
    wheel = wheel.replace(tmp_path / filename)

    with pytest.raises(PreparationError, match="incompatible"):
        validate_application_wheel(wheel, assessment, plan)


def test_package_generation_validates_application_wheel_before_acquisition_or_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "kit"
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail("uv acquisition must not run"),
    )

    with pytest.raises(PreparationError, match="requires --application-wheel"):
        generate_deployment_kit(repository, output)
    assert not output.exists()

    wrong = _make_application_wheel(tmp_path, target="installed_app.other:main")
    with pytest.raises(PreparationError, match="entry point disagrees"):
        generate_deployment_kit(repository, output, application_wheel=wrong)
    assert not output.exists()


@pytest.mark.parametrize("output_name", ["source", "."])
def test_package_generation_rejects_output_root_that_contains_application_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, output_name: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    wheel = _make_application_wheel(tmp_path)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = source if output_name == "source" else tmp_path
    original = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail("unsafe package output must block before acquisition"),
    )

    with pytest.raises(PreparationError, match="must be external"):
        generate_deployment_kit(
            repository,
            output,
            application_wheel=wheel,
            bootstrap_mode="online_cmd",
        )

    assert {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    } == original
    assert not (source / "deployment").exists()


def test_package_generation_rejects_nested_output_before_writes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")

    with pytest.raises(PreparationError, match="may not be nested"):
        generate_deployment_kit(
            repository,
            source / "kit",
            application_wheel=_make_application_wheel(tmp_path),
            bootstrap_mode="online_cmd",
        )
    assert not (source / "kit").exists()


def test_source_mode_in_place_generation_remains_supported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURES / "prepared_gui", source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )

    result = generate_deployment_kit(repository, source, bootstrap_mode="online_cmd")

    assert result.generated
    assert (source / "prepared_gui.py").is_file()
    assert (source / "deployment/manifest.json").is_file()


def test_package_dry_run_reports_missing_valid_and_invalid_application_wheels(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "kit"

    missing = generate_deployment_kit(repository, output, dry_run=True)
    assert missing.preview.deployment_mode == "package"
    assert missing.preview.source_roots == []
    assert missing.preview.application_wheel_required
    assert missing.preview.readiness_before == "BLOCKED_PENDING_APPLICATION_WHEEL"
    assert not output.exists()

    wheel = _make_application_wheel(tmp_path)
    valid = generate_deployment_kit(repository, output, application_wheel=wheel, dry_run=True)
    assert not valid.preview.application_wheel_required
    assert valid.preview.source_roots == []
    assert valid.preview.application_artifact.sha256
    assert f"deployment/application/{wheel.name}" in valid.preview.files_to_create
    assert "code/main.py" not in valid.preview.files_to_create
    assert not output.exists()

    wheel.unlink()
    malformed = tmp_path / wheel.name
    malformed.write_bytes(b"not a zip")
    with pytest.raises(PreparationError, match="Malformed application wheel"):
        generate_deployment_kit(
            repository, output, application_wheel=malformed, dry_run=True
        )
    assert not output.exists()


def test_deployment_fingerprint_separates_mode_and_exact_application_wheel_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    package_plan = create_deployment_plan(assessment, repository_root=source)
    wheel = _make_application_wheel(tmp_path)
    artifact, _ = validate_application_wheel(wheel, assessment, package_plan)

    def manifest(plan, application):
        return build_deployment_manifest(
            plan,
            source,
            bootstrap_mode="online_cmd",
            system_certs=False,
            approved_artifacts=[],
            application_artifact=application,
            bundled_uv_sha256=None,
            referenced_files=[],
        )

    original = manifest(package_plan, artifact)
    renamed_wheel = tmp_path / "mapped_app-1.2.3-1-py3-none-any.whl"
    renamed_wheel.write_bytes(wheel.read_bytes())
    renamed_artifact, _ = validate_application_wheel(
        renamed_wheel, assessment, package_plan
    )
    renamed = manifest(package_plan, renamed_artifact)
    assert renamed.deployment_fingerprint == original.deployment_fingerprint

    _rewrite_application_wheel(
        wheel, additions={"installed_app/additional-runtime-data.txt": "changed bytes"}
    )
    changed_artifact, _ = validate_application_wheel(wheel, assessment, package_plan)
    changed = manifest(package_plan, changed_artifact)
    assert changed.deployment_fingerprint != original.deployment_fingerprint

    source_plan = package_plan.model_copy(deep=True)
    source_plan.deployment_mode = "source"
    source_plan.runtime.environment_variables["PYTHONPATH"] = "%PROJECT_ROOT%"
    source_manifest = manifest(source_plan, None)
    assert source_manifest.application_artifact is None
    assert source_manifest.deployment_fingerprint != original.deployment_fingerprint


def test_package_mode_release_is_deterministic_and_survives_extraction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    wheel = _make_application_wheel(tmp_path)
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    generated = generate_deployment_kit(repository, kit, application_wheel=wheel)

    first = package_deployment_kit(kit, output_directory=tmp_path / "dist-one")
    second = package_deployment_kit(kit, output_directory=tmp_path / "dist-two")
    assert first.manifest.deployment_mode == "package"
    assert (
        first.manifest.application_artifact.sha256
        == generated.manifest.application_artifact.sha256
    )
    assert first.manifest.deployment_fingerprint == generated.manifest.deployment_fingerprint
    assert first.manifest.zip_sha256 == second.manifest.zip_sha256
    assert hashlib.sha256(Path(first.zip_path).read_bytes()).hexdigest().upper() == (
        first.manifest.zip_sha256
    )
    with zipfile.ZipFile(first.zip_path) as bundle:
        names = set(bundle.namelist())
    assert f"deployment/application/{wheel.name}" in names
    assert not any(name.startswith("code/") for name in names)

    extracted = tmp_path / "extracted"
    safe_extract_zip(Path(first.zip_path), extracted)
    assert validate_static_kit(extracted).final_state.value == "STATIC_VALID"
    smoke = Path(first.smoke_test_path).read_text(encoding="utf-8")
    assert "first-party application artifact is mapped-app==1.2.3" in smoke


def test_package_regeneration_removes_unchanged_obsolete_application_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    old_wheel = _make_application_wheel(tmp_path)
    new_wheel = tmp_path / "mapped_app-1.2.3-1-py3-none-any.whl"
    new_wheel.write_bytes(old_wheel.read_bytes())
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    generate_deployment_kit(repository, kit, application_wheel=old_wheel)

    generate_deployment_kit(repository, kit, application_wheel=new_wheel)

    old_staged = kit / "deployment/application" / old_wheel.name
    new_staged = kit / "deployment/application" / new_wheel.name
    index = json.loads((kit / "deployment/generated-files.json").read_text(encoding="utf-8"))
    indexed_paths = {item["path"] for item in index["files"]}
    report = validate_static_kit(kit)
    packaged = package_deployment_kit(kit, output_directory=tmp_path / "release")
    assert not old_staged.exists()
    assert new_staged.is_file()
    assert f"deployment/application/{old_wheel.name}" not in indexed_paths
    assert f"deployment/application/{new_wheel.name}" in indexed_paths
    assert report.final_state.value == "STATIC_VALID"
    assert not any(
        item.code == "NO_UNINDEXED_STAGED_FILES" and item.status.value == "fail"
        for item in report.static_checks
    )
    assert packaged.generated


def test_package_regeneration_protects_modified_obsolete_application_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    old_wheel = _make_application_wheel(tmp_path)
    new_wheel = tmp_path / "mapped_app-1.2.3-1-py3-none-any.whl"
    new_wheel.write_bytes(old_wheel.read_bytes())
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    kit = tmp_path / "kit"
    generate_deployment_kit(repository, kit, application_wheel=old_wheel)
    old_staged = kit / "deployment/application" / old_wheel.name
    modified = b"developer-modified obsolete artifact"
    old_staged.write_bytes(modified)
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail(
            "modified obsolete output must block before uv acquisition"
        ),
    )

    with pytest.raises(PreparationError, match="obsolete previously generated file was modified"):
        generate_deployment_kit(repository, kit, application_wheel=new_wheel)

    assert old_staged.read_bytes() == modified
    assert not (kit / "deployment/application" / new_wheel.name).exists()


def test_generate_and_all_cli_propagate_first_party_application_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    wheel = _make_application_wheel(tmp_path)
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )

    generate_output = tmp_path / "generated"
    assert (
        main(
            [
                "generate",
                str(source),
                "--output-dir",
                str(generate_output),
                "--application-wheel",
                str(wheel),
                "--bootstrap",
                "online_cmd",
            ]
        )
        == 0
    )
    assert (generate_output / "deployment/application" / wheel.name).is_file()

    all_output = tmp_path / "all-output"
    assert (
        main(
            [
                "all",
                str(source),
                "--output-dir",
                str(all_output),
                "--application-wheel",
                str(wheel),
                "--bootstrap",
                "online_cmd",
            ]
        )
        == 0
    )
    assert (all_output / "deployment-kit/deployment/application" / wheel.name).is_file()
    assert list((all_output / "distribution").glob("*.zip"))
    assert (all_output / "reports/assessment.json").is_file()
    assert (all_output / "reports/assessment.md").is_file()
    assert (all_output / "reports/deployment-plan.json").is_file()
    assert (all_output / "reports/deployment-plan.md").is_file()

    missing_output = tmp_path / "missing-output"
    assert (
        main(
            [
                "all",
                str(source),
                "--output-dir",
                str(missing_output),
                "--bootstrap",
                "online_cmd",
            ]
        )
        == 2
    )
    assert (missing_output / "reports/assessment.json").is_file()
    assert (missing_output / "reports/deployment-plan.json").is_file()
    assert not (missing_output / "deployment-kit").exists()
    assert not (missing_output / "distribution").exists()
    output_text = capsys.readouterr().out
    assert "--application-wheel" in output_text
    assert "Source roots: none (installed-project mode)" in output_text

    help_text = build_parser().format_help()
    generate_help = build_parser()._subparsers._group_actions[0].choices["generate"].format_help()
    assert "first-party application wheel" in generate_help
    assert "approved wheel" in generate_help
    assert help_text

def test_git_source_staging_allows_untracked_unselected_application_like_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        """[project]
name = "tracked-app"
version = "1.0.0"
dependencies = []
[project.scripts]
tracked-app = "app:main"
[tool.setuptools]
py-modules = ["app"]
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text(
        "version = 1\nrevision = 3\nrequires-python = \">=3.11\"\n",
        encoding="utf-8",
    )
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    (source / "docs").mkdir()
    (source / "docs/local_helper.py").write_text("VALUE = 1\n", encoding="utf-8")

    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    staged = _staging_files(source, assessment, plan, include=True)

    assert assessment.repository.revision
    assert "app.py" in staged
    assert "docs/local_helper.py" not in staged


def test_git_source_staging_blocks_untracked_selected_import_and_stages_after_commit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='tracked-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\ntracked-app='main:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "main.py").write_text(
        "from helper import VALUE\ndef main(): return VALUE\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    helper = source / "helper.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    assert any(
        item.path == "helper.py" and item.role.value == "application_source"
        for item in assessment.file_inventory
    )
    with pytest.raises(
        PreparationError, match="Selected deployment inputs must be tracked.*helper.py"
    ):
        _staging_files(source, assessment, plan, include=True)

    subprocess.run(["git", "-C", str(source), "add", "helper.py"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "track helper"], check=True)
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    staged = _staging_files(source, assessment, plan, include=True)

    assert _selected_deployment_paths(source, assessment, plan) <= staged.keys()
    assert "helper.py" in staged


def test_git_source_staging_blocks_untracked_selected_runtime_resource(tmp_path: Path) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='tracked-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\ntracked-app='main:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "main.py").write_text(
        "from pathlib import Path\nSTATE = Path(__file__).with_name('state.json').read_text()\n"
        "def main(): return STATE\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    (source / "state.json").write_text("{}\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    assert any(
        item.path == "state.json" and item.role.value == "runtime_resource"
        for item in assessment.file_inventory
    )
    with pytest.raises(
        PreparationError, match="Selected deployment inputs must be tracked.*state.json"
    ):
        _staging_files(source, assessment, plan, include=True)


def test_git_source_staging_blocks_untracked_authoritative_package_data(
    tmp_path: Path,
) -> None:
    source = tmp_path / "git-source"
    (source / "app/data").mkdir(parents=True)
    (source / "app/__init__.py").write_text("", encoding="utf-8")
    (source / "app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    data = source / "app/data/default.json"
    (source / "pyproject.toml").write_text(
        "[project]\nname = 'package-data-app'\nversion = '1.0.0'\ndependencies = []\n"
        "[project.scripts]\npackage-data-app = 'app.main:main'\n"
        "[tool.setuptools]\npackages = ['app']\n"
        "[tool.setuptools.package-data]\napp = ['data/*.json']\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    data.write_text("{}\n", encoding="utf-8")
    unrelated = source / "untracked-runtime-looking.json"
    unrelated.write_text("{}\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match="package-data runtime resources.*untracked"):
        _staging_files(source, assessment, plan, include=True)

    assert data.is_file()
    assert unrelated.is_file()


def test_prepare_lock_stages_only_lock_created_by_current_authorized_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='lock-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\nlock-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    (source / "docs").mkdir()
    unrelated = source / "docs/local_runtime.py"
    unrelated.write_text("VALUE = 'untracked'\n", encoding="utf-8")
    lock_bytes = b"version = 1\nrevision = 3\nrequires-python = \">=3.11\"\n"
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )

    def create_lock(root: Path, *args, **kwargs) -> LockPreparationResult:
        path = root / "uv.lock"
        assert not path.exists()
        path.write_bytes(lock_bytes)
        return LockPreparationResult(path=path, created=True, checked=True, commands=())

    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile", create_lock
    )
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    output = tmp_path / "external-kit"

    result = generate_deployment_kit(
        repository,
        output,
        prepare_lock=True,
        bootstrap_mode="online_cmd",
    )

    assert result.generated
    assert (output / "uv.lock").read_bytes() == lock_bytes
    assert not (output / unrelated.name).exists()
    assert result.preview.repository_files_changed == [str(source / "uv.lock")]
    index = json.loads((output / "deployment/generated-files.json").read_text(encoding="utf-8"))
    lock_entry = next(item for item in index["files"] if item["path"] == "uv.lock")
    assert lock_entry["sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    status = subprocess.run(
        ["git", "-C", str(source), "status", "--short"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert "?? uv.lock" in status
    assert "?? docs/" in status


def test_preexisting_untracked_lock_does_not_bypass_git_staging_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='lock-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\nlock-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    (source / "uv.lock").write_text("untracked lock\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(
        PreparationError, match="Selected deployment inputs must be tracked.*uv.lock"
    ):
        _staging_files(source, assessment, plan, include=True)


def test_git_source_staging_blocks_dirty_tracked_inputs_but_ignores_unrelated_docs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "docs").mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='clean-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\nclean-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    (source / "docs/readme.md").write_text("docs\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")

    (source / "docs/readme.md").write_text("unrelated docs change\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    assert "app.py" in _staging_files(source, assessment, plan, include=True)

    (source / "app.py").write_text("def main(): return 1\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)
    with pytest.raises(PreparationError, match="differ from recorded source revision.*app.py"):
        _staging_files(source, assessment, plan, include=True)


def _committed_source_fixture(tmp_path: Path) -> tuple[Path, MaterializedRepository]:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "docs").mkdir()
    (source / "data").mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='dirty-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\ndirty-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "app.py").write_text(
        "from pathlib import Path\n"
        "STATE = Path(__file__).with_name('state.json').read_text()\n"
        "def main(): return STATE\n",
        encoding="utf-8",
    )
    (source / "state.json").write_text("{}\n", encoding="utf-8")
    (source / "docs/readme.md").write_text("documentation\n", encoding="utf-8")
    (source / ".gitignore").write_text("# root policy\n", encoding="utf-8")
    (source / "data/.gitignore").write_text("# nested policy\n", encoding="utf-8")
    (source / "data/observed.txt").write_text("analysis candidate\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    return source, MaterializedRepository(
        root=source, source=str(source), source_kind="local"
    )


def _nested_committed_source_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, MaterializedRepository]:
    """Create a selected project beneath, rather than at, a Git worktree root."""

    worktree = tmp_path / "monorepo"
    source = worktree / "projects" / "example"
    (source / "docs").mkdir(parents=True)
    (source / "data").mkdir()
    (worktree / "other-project").mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='nested-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\nnested-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    (source / ".gitignore").write_text("# selected-project policy\n", encoding="utf-8")
    (source / "data/.gitignore").write_text("# nested selected-project policy\n", encoding="utf-8")
    (source / "docs/readme.md").write_text("documentation\n", encoding="utf-8")
    (worktree / "other-project/readme.md").write_text("sibling\n", encoding="utf-8")
    (worktree / ".gitignore").write_text("# enclosing-worktree policy\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(worktree), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(worktree), "add", "."], check=True)
    subprocess.run(["git", "-C", str(worktree), "commit", "-qm", "fixture"], check=True)
    return worktree, source, MaterializedRepository(
        root=source, source=str(source), source_kind="local"
    )


@pytest.mark.parametrize("operation", ["modified", "deleted", "staged_rename"])
def test_nested_git_repository_provenance_uses_selected_root_paths(
    tmp_path: Path, operation: str
) -> None:
    worktree, source, repository = _nested_committed_source_fixture(tmp_path)
    if operation == "modified":
        (source / "app.py").write_text("def main(): return 1\n", encoding="utf-8")
    elif operation == "deleted":
        (source / "app.py").unlink()
    else:
        subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "mv",
                "projects/example/app.py",
                "projects/example/docs/app.py",
            ],
            check=True,
        )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    tracked = _git_tracked_paths(source, required=True)
    assert ("docs/app.py" if operation == "staged_rename" else "app.py") in tracked
    with pytest.raises(PreparationError, match="recorded source revision.*app.py"):
        _staging_files(source, assessment, plan, include=True)


def test_nested_git_repository_ignores_sibling_and_documentation_changes(tmp_path: Path) -> None:
    worktree, source, repository = _nested_committed_source_fixture(tmp_path)
    (worktree / "other-project/readme.md").write_text("changed sibling\n", encoding="utf-8")
    (worktree / "other-project/untracked.py").write_text("VALUE = 1\n", encoding="utf-8")
    (worktree / ".gitignore").write_text("sibling-local/\n", encoding="utf-8")
    (source / "docs/readme.md").write_text("changed documentation\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert "app.py" in staged
    assert all(not path.startswith("projects/example/") for path in staged)


@pytest.mark.parametrize("relative", [".gitignore", "data/.gitignore"])
def test_nested_git_repository_guards_selected_ignore_policy(
    tmp_path: Path, relative: str
) -> None:
    _worktree, source, repository = _nested_committed_source_fixture(tmp_path)
    (source / relative).write_text("local/\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match=f"recorded source revision.*{relative}"):
        _staging_files(source, assessment, plan, include=True)


def test_clean_git_source_fixture_stages_and_previews_normally(tmp_path: Path) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)
    preview = generate_deployment_kit(
        repository,
        tmp_path / "kit",
        bootstrap_mode="online_cmd",
        dry_run=True,
    ).preview

    assert {"app.py", "state.json"} <= staged.keys()
    assert {"app.py", "state.json"} <= set(preview.files_to_create)
    assert ".gitignore" not in staged
    assert "data/.gitignore" not in staged


@pytest.mark.parametrize("relative", [".gitignore", "data/.gitignore"])
def test_git_source_staging_blocks_modified_tracked_analysis_policy(
    tmp_path: Path, relative: str
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    recorded = assess_repository(repository)
    policy = source / relative
    policy.write_text(policy.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)

    assert assessment.repository.revision in str(caught.value)
    assert relative in str(caught.value).replace("\\", "/")
    assert assessment.repository.fingerprint != recorded.repository.fingerprint
    if relative == ".gitignore":
        with pytest.raises(PreparationError, match="recorded source revision.*gitignore"):
            generate_deployment_kit(
                repository,
                tmp_path / "kit",
                bootstrap_mode="online_cmd",
                dry_run=True,
            )


@pytest.mark.parametrize("operation", ["deleted", "renamed"])
def test_git_source_staging_blocks_missing_tracked_analysis_policy(
    tmp_path: Path, operation: str
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    policy = source / "data/.gitignore"
    if operation == "deleted":
        policy.unlink()
    else:
        policy.rename(source / "data/.gitignore-renamed")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)

    assert assessment.repository.revision in str(caught.value)
    assert "data/.gitignore" in str(caught.value).replace("\\", "/")


@pytest.mark.parametrize("relative", [".gitignore", "local/.gitignore"])
def test_git_source_staging_blocks_untracked_analysis_policy(
    tmp_path: Path, relative: str
) -> None:
    source = tmp_path / "git-source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        "[project]\nname='policy-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\npolicy-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (source / "app.py").write_text("def main(): return 0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "PDB Test"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "pdb@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    policy = source / relative
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("# local analysis policy\n", encoding="utf-8")
    if policy.parent != source:
        (policy.parent / "candidate.py").write_text("VALUE = 1\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match="Untracked .*gitignore"):
        _staging_files(source, assessment, plan, include=True)
    if relative == ".gitignore":
        with pytest.raises(PreparationError, match="Untracked .*gitignore"):
            generate_deployment_kit(
                repository,
                tmp_path / "kit",
                bootstrap_mode="online_cmd",
                dry_run=True,
            )


def test_git_source_staging_blocks_deleted_tracked_application_source(
    tmp_path: Path,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    (source / "app.py").unlink()
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)
    assert assessment.repository.revision in str(caught.value)
    assert "app.py" in str(caught.value)

    with pytest.raises(PreparationError, match="recorded source revision.*app.py"):
        generate_deployment_kit(
            repository,
            tmp_path / "kit",
            bootstrap_mode="online_cmd",
            dry_run=True,
        )


def test_git_source_staging_blocks_unstaged_application_source_rename(
    tmp_path: Path,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    (source / "app.py").rename(source / "renamed_app.py")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)
    assert assessment.repository.revision in str(caught.value)
    assert "app.py" in str(caught.value)


def _committed_runtime_rename_fixture(
    tmp_path: Path,
) -> tuple[Path, MaterializedRepository]:
    source, repository = _committed_source_fixture(tmp_path)
    (source / "helper.py").write_text("VALUE = 'runtime input'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "helper.py"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "add runtime helper"], check=True)
    return source, repository


def test_git_staged_runtime_rename_to_documentation_blocks_provenance(
    tmp_path: Path,
) -> None:
    source, repository = _committed_runtime_rename_fixture(tmp_path)
    subprocess.run(["git", "-C", str(source), "mv", "helper.py", "docs/helper.py"], check=True)
    default_changed = subprocess.run(
        ["git", "-C", str(source), "diff", "--name-only", "-z", "HEAD", "--"],
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    assert b"docs/helper.py" in default_changed
    assert b"helper.py" not in default_changed
    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)
    assert assessment.repository.revision in str(caught.value)
    assert "helper.py" in str(caught.value)


def test_git_staged_runtime_rename_to_runtime_path_blocks_provenance(
    tmp_path: Path,
) -> None:
    source, repository = _committed_runtime_rename_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(source), "mv", "helper.py", "renamed_helper.py"], check=True
    )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match="helper.py|renamed_helper.py"):
        _staging_files(source, assessment, plan, include=True)


def test_git_staged_documentation_rename_remains_allowed(tmp_path: Path) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(source), "mv", "docs/readme.md", "docs/renamed.md"], check=True
    )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert {"app.py", "state.json"} <= staged.keys()
    assert "docs/renamed.md" not in staged


def test_git_head_symlink_does_not_poison_unrelated_documentation_provenance(
    tmp_path: Path,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    external = tmp_path / "external-content.py"
    external.write_text("EXTERNAL = 'must not be read from HEAD snapshot'\n", encoding="utf-8")
    link = source / "docs/unrelated-link.py"
    try:
        link.symlink_to(external)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Git symlink fixture is unavailable: {exc}")
    subprocess.run(["git", "-C", str(source), "add", "docs/unrelated-link.py"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "add unrelated link"], check=True)
    (source / "docs/readme.md").write_text("changed documentation\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert {"app.py", "state.json"} <= staged.keys()
    assert "docs/unrelated-link.py" not in staged
    assert external.read_text(encoding="utf-8").startswith("EXTERNAL")

    replacement = tmp_path / "replacement-content.py"
    replacement.write_text("EXTERNAL = 'changed'\n", encoding="utf-8")
    link.unlink()
    link.symlink_to(replacement)
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match="docs/unrelated-link.py"):
        _staging_files(source, assessment, plan, include=True)


def test_git_staged_gitignore_rename_blocks_provenance(tmp_path: Path) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(source), "mv", "data/.gitignore", "data/renamed.ignore"],
        check=True,
    )
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError, match="data/.gitignore"):
        _staging_files(source, assessment, plan, include=True)


@pytest.mark.parametrize("operation", ["modified", "deleted"])
def test_git_source_staging_blocks_dirty_tracked_runtime_resource(
    tmp_path: Path,
    operation: str,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    resource = source / "state.json"
    if operation == "modified":
        resource.write_text('{"changed": true}\n', encoding="utf-8")
    else:
        resource.unlink()
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)
    assert assessment.repository.revision in str(caught.value)
    assert "state.json" in str(caught.value)


@pytest.mark.parametrize(
    ("relative", "operation"),
    [
        ("pyproject.toml", "modified"),
        ("pyproject.toml", "deleted"),
        ("uv.lock", "modified"),
        ("uv.lock", "deleted"),
    ],
)
def test_git_source_staging_blocks_dirty_tracked_project_metadata(
    tmp_path: Path,
    relative: str,
    operation: str,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    path = source / relative
    if operation == "modified":
        path.write_text(path.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    else:
        path.unlink()
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    with pytest.raises(PreparationError) as caught:
        _staging_files(source, assessment, plan, include=True)
    assert assessment.repository.revision in str(caught.value)
    assert relative in str(caught.value)


def test_git_source_staging_allows_deleted_unrelated_documentation(
    tmp_path: Path,
) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    (source / "docs/readme.md").unlink()
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert {"app.py", "state.json"} <= staged.keys()
    assert "docs/readme.md" not in staged


def test_git_source_staging_allows_untracked_unrelated_file(tmp_path: Path) -> None:
    source, repository = _committed_source_fixture(tmp_path)
    (source / "local-notes.txt").write_text("not a deployment input\n", encoding="utf-8")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert {"app.py", "state.json"} <= staged.keys()
    assert "local-notes.txt" not in staged


def test_source_staging_includes_required_root_nested_and_adjacent_resources(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "package/resources").mkdir(parents=True)
    (source / "runtime").mkdir()
    (source / "package/__init__.py").write_text("", encoding="utf-8")
    (source / "package/app.py").write_text(
        "from pathlib import Path\n"
        "HERE=Path(__file__).parent\n"
        "A=(HERE/'resources/nested.json').read_text()\n"
        "B=Path('root-data.json').read_text()\n"
        "C=Path('runtime/adjacent.txt').read_text()\n"
        "def main(): return A+B+C\n",
        encoding="utf-8",
    )
    (source / "package/resources/nested.json").write_text("{}", encoding="utf-8")
    (source / "root-data.json").write_text("root", encoding="utf-8")
    (source / "runtime/adjacent.txt").write_text("adjacent", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        "[project]\nname='resource-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\nresource-app='package.app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")
    assessment = assess_repository(repository)
    plan = create_deployment_plan(assessment, repository_root=source)

    staged = _staging_files(source, assessment, plan, include=True)

    assert plan.deployment_mode == "source"
    assert {
        "package/__init__.py",
        "package/app.py",
        "package/resources/nested.json",
        "root-data.json",
        "runtime/adjacent.txt",
    } <= staged.keys()


def test_source_runtime_file_cannot_collide_with_generated_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    launcher = source / "deployment/README-deployment.txt"
    launcher.parent.mkdir()
    launcher.write_text("runtime payload", encoding="utf-8")
    (source / "app.py").write_text(
        "from pathlib import Path\n"
        "PAYLOAD=Path('deployment/README-deployment.txt').read_text()\n"
        "def main(): return PAYLOAD\n",
        encoding="utf-8",
    )
    (source / "pyproject.toml").write_text(
        "[project]\nname='collision-app'\nversion='1.0'\ndependencies=[]\n"
        "[project.scripts]\ncollision-app='app:main'\n",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")

    preview = generate_deployment_kit(repository, tmp_path / "kit", dry_run=True).preview

    assert preview.deployment_mode == "source"
    assert preview.collisions == [
        "deployment/README-deployment.txt (runtime source conflicts with a generated path)"
    ]


def test_dry_run_makes_no_output_or_lock(tmp_path: Path) -> None:
    repository = _repository("target_app")
    output = tmp_path / "kit"

    result = generate_deployment_kit(
        repository,
        output,
        prepare_lock=True,
        dry_run=True,
    )

    assert not output.exists()
    assert not (repository.root / "uv.lock").exists()
    assert not result.generated
    assert "uv.lock" in result.preview.files_to_create
    assert any("Create uv.lock" in item for item in result.preview.developer_actions)


def test_application_wheel_tilde_path_works_for_cli_dry_run_and_generation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    fake_home = tmp_path / "home"
    wheel_directory = fake_home / "dist"
    wheel_directory.mkdir(parents=True)
    wheel = _make_application_wheel(wheel_directory)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    tilde_wheel = Path("~/dist") / wheel.name

    assert (
        main(
            [
                "generate",
                str(source),
                "--output-dir",
                str(tmp_path / "preview-kit"),
                "--application-wheel",
                str(tilde_wheel),
                "--bootstrap",
                "online_cmd",
                "--dry-run",
            ]
        )
        == 0
    )

    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    output = tmp_path / "kit"
    result = generate_deployment_kit(
        MaterializedRepository(root=source, source=str(source), source_kind="local"),
        output,
        application_wheel=tilde_wheel,
        bootstrap_mode="online_cmd",
    )

    assert result.generated
    assert (output / "deployment/application" / wheel.name).is_file()


def _wheel_alias(alias: Path, target: Path) -> Path:
    try:
        alias.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"wheel alias symlink is unavailable: {exc}")
    return alias


def test_validated_artifact_models_are_the_generated_destination_authority() -> None:
    plan = _plan("optional_map_app", ["map"])
    approved = ApprovedArtifact(
        distribution_name="proxy-tools",
        version="0.1.0",
        filename="proxy_tools-0.1.0-py3-none-any.whl",
        sha256="a" * 64,
    )
    application = ApplicationArtifact(
        distribution_name="mapped-app",
        version="1.2.3",
        filename="mapped_app-1.2.3-py3-none-any.whl",
        sha256="b" * 64,
        entry_point_name="mapped-app",
        entry_point_target="installed_app.main:main",
    )

    paths = _planned_generated_paths(
        plan,
        "online_cmd",
        [(approved, Path("reviewed-latest.whl"))],
        (application, Path("latest.whl")),
    )

    assert "deployment/wheels/proxy_tools-0.1.0-py3-none-any.whl" in paths
    assert "deployment/application/mapped_app-1.2.3-py3-none-any.whl" in paths
    assert not any("latest.whl" in path for path in paths)


def test_application_wheel_preview_and_write_use_validated_filename(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_mapped_project(source)
    wheel = _make_application_wheel(tmp_path)
    alias = _wheel_alias(tmp_path / "latest.whl", wheel)
    output = tmp_path / "kit"
    destination = output / "deployment/application" / wheel.name
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"unowned destination")
    repository = MaterializedRepository(root=source, source=str(source), source_kind="local")

    preview = generate_deployment_kit(
        repository, output, application_wheel=alias, bootstrap_mode="online_cmd", dry_run=True
    ).preview

    assert f"deployment/application/{wheel.name}" in preview.collisions
    assert f"deployment/application/{alias.name}" not in preview.files_to_create
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: pytest.fail("validated destination collision must block early"),
    )
    with pytest.raises(PreparationError, match=wheel.name):
        generate_deployment_kit(
            repository, output, application_wheel=alias, bootstrap_mode="online_cmd"
        )
    assert destination.read_bytes() == b"unowned destination"

    destination.unlink()
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    result = generate_deployment_kit(
        repository, output, application_wheel=alias, bootstrap_mode="online_cmd"
    )

    assert result.generated
    assert destination.is_file()
    assert not (output / "deployment/application" / alias.name).exists()


def test_dependency_artifact_preview_uses_validated_filename(tmp_path: Path) -> None:
    wheel = _make_wheel(tmp_path)
    alias = _wheel_alias(tmp_path / "reviewed-latest.whl", wheel)
    output = tmp_path / "kit"
    destination = output / "deployment/wheels" / wheel.name
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"unowned destination")

    preview = generate_deployment_kit(
        _repository("optional_map_app"),
        output,
        selected_extras=["map"],
        artifact_values=[f"proxy-tools={alias}"],
        bootstrap_mode="online_cmd",
        dry_run=True,
    ).preview

    assert f"deployment/wheels/{wheel.name}" in preview.collisions
    assert f"deployment/wheels/{alias.name}" not in preview.files_to_create
    assert destination.read_bytes() == b"unowned destination"


def test_dry_run_reports_unowned_output_collision(tmp_path: Path) -> None:
    output = tmp_path / "kit"
    output.mkdir()
    (output / "Run Prepared Gui.bat").write_text("user file", encoding="utf-8")

    result = generate_deployment_kit(_repository("prepared_gui"), output, dry_run=True)

    assert result.preview.collisions == ["Run Prepared Gui.bat"]


def test_generation_writes_structurally_valid_kit_and_protects_edits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_uv = tmp_path / "developer-uv.exe"
    fake_uv.write_bytes(b"verified uv 0.12.5")
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.acquire_pinned_uv",
        lambda *args, **kwargs: fake_uv,
    )
    monkeypatch.setattr(
        "python_deployment_builder.generation.generator.prepare_lockfile",
        lambda root, *args, **kwargs: LockPreparationResult(
            path=root / "uv.lock", created=False, checked=True, commands=()
        ),
    )
    output = tmp_path / "kit"

    result = generate_deployment_kit(_repository("prepared_gui"), output)

    assert result.generated and result.manifest is not None
    assert (output / "deployment" / "manifest.json").is_file()
    assert (output / "deployment" / "bootstrap" / "uv.exe").read_bytes() == fake_uv.read_bytes()
    assert (output / "prepared_gui.py").is_file()
    assert not list(output.rglob("*.ps1"))

    run_bat = output / "Run Prepared Gui.bat"
    run_bat.write_text("locally modified", encoding="utf-8")
    preview = generate_deployment_kit(
        _repository("prepared_gui"), output, dry_run=True
    ).preview
    assert any("previously generated file was modified" in item for item in preview.collisions)


def test_manifest_renders_flat_source_system_certs_and_selected_extra(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path)
    approved, _path = validate_approved_wheel(f"proxy-tools={wheel}", plan)
    manifest = build_deployment_manifest(
        plan,
        FIXTURES / "optional_map_app",
        bootstrap_mode="online_cmd",
        system_certs=True,
        approved_artifacts=[approved],
        bundled_uv_sha256=None,
        referenced_files=["pyproject.toml", "uv.lock"],
    )

    assert manifest.source_roots == ["."]
    assert manifest.system_certs
    assert manifest.selected_extras == ["map"]
    assert manifest.sync_arguments[-2:] == ["--no-install-package", "proxy-tools"]
    assert manifest.approved_artifacts[0].sha256


def test_src_manifest_uses_src_root() -> None:
    plan = _plan("target_app")
    lock = FIXTURES / "target_app" / "uv.lock"
    lock.write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n', encoding="utf-8"
    )
    try:
        manifest = build_deployment_manifest(
            plan,
            FIXTURES / "target_app",
            bootstrap_mode="online_cmd",
            system_certs=False,
            approved_artifacts=[],
            bundled_uv_sha256=None,
            referenced_files=["pyproject.toml", "uv.lock"],
        )
    finally:
        lock.unlink()
    assert manifest.source_roots == ["src"]


def test_templates_are_thin_and_forbid_prohibited_shells(tmp_path: Path) -> None:
    plan = _plan()
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    owned, manifest = _render_owned_files(
        plan,
        FIXTURES / "prepared_gui",
        bootstrap_mode="bundled_uv",
        system_certs=False,
        approved=[],
        bundled_uv=fake_uv,
    )
    owned["deployment/generated-files.json"] = b"{}"
    files = {
        "pyproject.toml": (FIXTURES / "prepared_gui" / "pyproject.toml").read_bytes(),
        "uv.lock": (FIXTURES / "prepared_gui" / "uv.lock").read_bytes(),
        **owned,
    }

    checks = validate_rendered_files(
        files, manifest, generated_paths=set(owned), secret_values=[]
    )

    text = b"\n".join(owned.values()).lower()
    assert b"powershell.exe" not in text
    assert b"pwsh.exe" not in text
    assert b"executionpolicy" not in text
    assert not any(path.endswith(".ps1") for path in owned)
    assert "deployment/bootstrap/uv.exe" in owned
    assert any(item.code == "NO_FORBIDDEN_SHELL" for item in checks)


def test_generation_structural_validation_scans_shared_textual_configuration_formats(
    tmp_path: Path,
) -> None:
    plan = _plan()
    fake_uv = tmp_path / "uv.exe"
    fake_uv.write_bytes(b"verified uv")
    owned, manifest = _render_owned_files(
        plan,
        FIXTURES / "prepared_gui",
        bootstrap_mode="bundled_uv",
        system_certs=False,
        approved=[],
        bundled_uv=fake_uv,
    )
    owned["deployment/runtime/settings.toml"] = b"api_key = 'sk-abcdefghijklmnop'\n"
    files = {
        "pyproject.toml": (FIXTURES / "prepared_gui" / "pyproject.toml").read_bytes(),
        "uv.lock": (FIXTURES / "prepared_gui" / "uv.lock").read_bytes(),
        **owned,
    }

    with pytest.raises(PreparationError, match="NO_SECRET_VALUES"):
        validate_rendered_files(files, manifest, generated_paths=set(owned), secret_values=[])


def test_uv_archive_rejects_traversal_and_hash_version_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "uv.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../uv.exe", b"bad")
    with pytest.raises(PreparationError, match="unsafe"):
        extract_verified_uv(archive, tmp_path / "uv.exe")

    result = subprocess.CompletedProcess([], 0, "uv 9.9.9", "")
    with pytest.raises(PreparationError, match="expected uv 0.12.5"):
        verify_uv_version(tmp_path / "uv.exe", "0.12.5", runner=lambda *a, **k: result)


def test_developer_uv_acquisition_rejects_sha_mismatch(tmp_path: Path) -> None:
    artifact = BootstrapArtifact(
        version="0.12.5",
        architecture="x86_64",
        url="https://example.invalid/uv.zip",
        sha256="0" * 64,
    )

    def opener(*args, **kwargs):
        return io.BytesIO(b"not the pinned archive")

    with pytest.raises(PreparationError, match="SHA-256 mismatch"):
        acquire_pinned_uv(artifact, cache_root=tmp_path, opener=opener)


def test_localized_certutil_output_is_parsed_structurally() -> None:
    expected = "4c" * 32
    spaced = " ".join(expected[index : index + 2] for index in range(0, 64, 2))
    output = f"SHA256-Hash von Datei:\n  {spaced}\nBefehl erfolgreich."
    assert parse_certutil_sha256(output) == expected
    with pytest.raises(PreparationError):
        parse_certutil_sha256("CertUtil: command failed")


def test_lock_preparation_requires_authorization_and_checks_existing(tmp_path: Path) -> None:
    plan = _plan()
    with pytest.raises(PreparationError, match="--prepare-lock"):
        prepare_lockfile(
            tmp_path,
            plan,
            tmp_path / "uv.exe",
            allow_create=False,
            system_certs=False,
        )

    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    result = prepare_lockfile(
        tmp_path,
        plan,
        tmp_path / "uv.exe",
        allow_create=False,
        system_certs=True,
        runner=runner,
    )
    assert result.checked and not result.created
    assert calls[0][0][-4:] == ["lock", "--check", "--python", "3.12"]
    assert calls[0][1]["env"]["UV_SYSTEM_CERTS"] == "true"


def test_explicit_lock_preparation_creates_then_checks(tmp_path: Path) -> None:
    plan = _plan()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["lock", "--python"]:
            (tmp_path / "uv.lock").write_text("created", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = prepare_lockfile(
        tmp_path,
        plan,
        tmp_path / "uv.exe",
        allow_create=True,
        system_certs=False,
        runner=runner,
    )

    assert result.created and result.checked
    assert calls[0][1:] == ["lock", "--python", "3.12"]
    assert calls[1][1:] == ["lock", "--check", "--python", "3.12"]


def test_approved_wheel_rejects_wrong_name_version_and_metadata(tmp_path: Path) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path)
    approved, path = validate_approved_wheel(f"proxy-tools={wheel}", plan)
    assert path == wheel.resolve()
    assert approved.distribution_name == "proxy-tools"
    assert approved.version == "0.1.0"
    assert approved.sha256

    with pytest.raises(PreparationError, match="name mismatch"):
        validate_approved_wheel(f"other={wheel}", plan)
    wrong = _make_wheel(tmp_path, version="0.2.0")
    with pytest.raises(PreparationError, match="version mismatch"):
        validate_approved_wheel(f"proxy-tools={wrong}", plan)


@pytest.mark.parametrize(
    ("requires_python", "accepted"),
    [
        (None, True),
        (">=3.11", True),
        (">=3.12,<3.13", True),
        ("==3.12.*", True),
        (">=3.9,!=3.9.0", True),
        (">=3.13", False),
        ("<3.12", False),
        (">=3.12.1", False),
        ("<3.12.1", False),
    ],
)
def test_approved_wheel_requires_python_uses_selected_minor_policy(
    tmp_path: Path, requires_python: str | None, accepted: bool
) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path, requires_python=requires_python)

    if accepted:
        assert validate_approved_wheel(f"proxy-tools={wheel}", plan)[0].filename == wheel.name
    else:
        with pytest.raises(PreparationError, match="Requires-Python"):
            validate_approved_wheel(f"proxy-tools={wheel}", plan)


@pytest.mark.parametrize(
    "values",
    [[">=three"], [">=3.11", "<3.12"]],
)
def test_approved_wheel_rejects_malformed_or_multiple_requires_python(
    tmp_path: Path, values: list[str]
) -> None:
    plan = _plan("optional_map_app", ["map"])
    wheel = _make_wheel(tmp_path, requires_python_values=values)

    with pytest.raises(PreparationError, match="Malformed Requires-Python"):
        validate_approved_wheel(f"proxy-tools={wheel}", plan)


def test_runtime_common_staleness_and_deletion_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    common = _load_template_module("runtime_common.py", monkeypatch)
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("project", encoding="utf-8")
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    app_root = local / "PythonDeploymentBuilder" / "apps" / "sample"
    environment = app_root / "env"
    (environment / "Scripts").mkdir(parents=True)
    (environment / "Scripts" / "python.exe").touch()
    (environment / "Scripts" / "pythonw.exe").touch()
    deployment = tmp_path / "deployment"
    application = deployment / "application"
    application.mkdir(parents=True)
    application_wheel = application / "sample-1.0-py3-none-any.whl"
    application_wheel.write_bytes(b"application wheel")
    monkeypatch.setattr(common, "deployment_directory", lambda: deployment)
    manifest = {
        "schema_version": "1.0",
        "application_id": "sample",
        "deployment_fingerprint": "fingerprint",
        "uv_version": "0.12.5",
        "python_version": "3.12",
        "pyproject_sha256": common.sha256_file(project / "pyproject.toml"),
        "lockfile_sha256": common.sha256_file(project / "uv.lock"),
        "selected_extras_fingerprint": "extras",
        "approved_artifacts": [],
        "application_artifact": {
            "filename": application_wheel.name,
            "sha256": common.sha256_file(application_wheel),
        },
        "runtime_paths": {
            "application_root": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample",
            "environment_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\env",
            "logs_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\logs",
            "state_path": r"%LOCALAPPDATA%\PythonDeploymentBuilder\apps\sample\state",
        },
    }
    common.write_state(manifest, project, "now")
    assert common.stale_reasons(manifest, project) == []
    application_wheel.write_bytes(b"changed application wheel")
    assert any("application artifact" in item for item in common.stale_reasons(manifest, project))
    application_wheel.write_bytes(b"application wheel")
    (project / "uv.lock").write_text("changed", encoding="utf-8")
    assert "lockfile_sha256 changed" in common.stale_reasons(manifest, project)
    with pytest.raises(common.DeploymentRuntimeError, match="unsafe"):
        common.safe_remove_environment(manifest, tmp_path / "unrelated")


def test_webview2_registry_probe_and_project_write_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    diagnostics = _load_template_module("diagnostics.py", monkeypatch)
    calls = []

    def read_value(hive, path, view):
        calls.append((hive, path, view))
        return "123.4.5.6" if hive == "HKCU" else None

    result = diagnostics.detect_webview2(read_value)
    assert result["installed"] and result["version"] == "123.4.5.6"
    assert any("F3017226-FE2A-4295-8BDF-00C3A9A7E4C5" in item[1] for item in calls)

    launch = _load_template_module("launch.py", monkeypatch)
    launch.probe_project_write(tmp_path, "Test App")
    assert not list(tmp_path.glob(".pdbuilder-write-probe-*"))


def test_gui_uses_pythonw_and_console_uses_python() -> None:
    manage = (TEMPLATE_ROOT / "manage.py").read_text(encoding="utf-8")
    assert '"pythonw.exe" if manifest["entry_point_kind"] == "gui" else "python.exe"' in manage
    bootstrap = (TEMPLATE_ROOT / "bootstrap.cmd.tmpl").read_text(encoding="utf-8")
    assert "curl.exe --fail --location" in bootstrap
    assert "certutil.exe -hashfile" in bootstrap
    assert "tar.exe -xf" in bootstrap


@pytest.mark.parametrize("helper", ["manage.py", "launch.py", "diagnostics.py"])
def test_generated_helpers_import_siblings_with_production_flags(
    helper: str, tmp_path: Path
) -> None:
    runtime = tmp_path / "deployment" / "runtime"
    runtime.mkdir(parents=True)
    for name in ("runtime_common.py", "manage.py", "launch.py", "diagnostics.py"):
        shutil.copy2(TEMPLATE_ROOT / name, runtime / name)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(TEMPLATE_ROOT.parent)
    result = subprocess.run(
        [sys.executable, "-B", "-E", "-s", str(runtime / helper), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    assert not (runtime / "__pycache__").exists()


def test_secret_value_is_not_rendered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = "sk-test-value-that-must-not-leak"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    plan = _plan("target_app")
    lock = FIXTURES / "target_app" / "uv.lock"
    lock.write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n', encoding="utf-8"
    )
    try:
        fake_uv = tmp_path / "uv.exe"
        fake_uv.write_bytes(b"verified")
        owned, _manifest = _render_owned_files(
            plan,
            FIXTURES / "target_app",
            bootstrap_mode="bundled_uv",
            system_certs=False,
            approved=[],
            bundled_uv=fake_uv,
        )
    finally:
        lock.unlink()
    assert secret.encode() not in b"".join(owned.values())
    assert secret not in redact_secrets(f"OPENAI_API_KEY={secret}")
