from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.inventory import _module_files
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.backends.uv_managed import UV_VERSION, UvManagedBackend
from python_deployment_builder.models import (
    DependencyAssessment,
    FindingStatus,
    RiskFinding,
    RiskSeverity,
    RuntimeRequirement,
    SuitabilityRating,
)
from python_deployment_builder.planning.index import (
    TargetMarkerApplicability,
    TargetMarkerEnvironmentError,
    inspect_dependency_wheels,
    marker_applies,
    target_marker_applicability,
    target_marker_applies,
    target_marker_environment,
)
from python_deployment_builder.planning.lockfile import inspect_uv_lock
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.planning.platforms import windows_finding_treatments
from python_deployment_builder.planning.policies import (
    MinorPythonCompatibility,
    minor_python_compatibility,
    safe_application_id,
)
from python_deployment_builder.reporting.markdown import render_deployment_plan_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _assess(name: str = "target_app"):
    root = FIXTURES / name
    return assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )


def _write_mode_project(
    root: Path,
    *,
    layout: str = "flat",
    target: str = "sample_app:main",
    buildable: bool = True,
    source_constraint: bool = False,
    mapped: bool = False,
) -> None:
    source = root / (
        "code" if mapped else "src/sample_app" if layout == "src" else "."
    )
    source.mkdir(parents=True, exist_ok=True)
    module = source / (
        "main.py" if mapped else "__init__.py" if layout == "src" else "sample_app.py"
    )
    module.write_text(
        (
            "from pathlib import Path\nRUNTIME = Path('runtime.json')\nRUNTIME.read_text()\n"
            if source_constraint
            else ""
        )
        + "def main(): return 0\n",
        encoding="utf-8",
    )
    if mapped:
        (source / "__init__.py").write_text("", encoding="utf-8")
    if source_constraint:
        (root / "runtime.json").write_text("{}\n", encoding="utf-8")
    build = (
        "[build-system]\nrequires = ['setuptools>=68']\n"
        "build-backend = 'setuptools.build_meta'\n"
        if buildable
        else ""
    )
    setuptools = ""
    if mapped:
        setuptools = (
            "[tool.setuptools]\npackages = ['installed_app']\n"
            "package-dir = {installed_app = 'code'}\n"
        )
    elif layout == "src":
        setuptools = "[tool.setuptools.packages.find]\nwhere = ['src']\n"
    (root / "pyproject.toml").write_text(
        build
        + "[project]\nname = 'sample-app'\nversion = '1.0.0'\ndependencies = []\n"
        + f"[project.scripts]\nsample-app = '{target}'\n"
        + setuptools,
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")


def _write_unresolved_backend_project(root: Path, *, backend: str, target: str) -> None:
    (root / "src/demo_app").mkdir(parents=True)
    (root / "src/demo_app/__init__.py").write_text("", encoding="utf-8")
    (root / "src/demo_app/main.py").write_text(
        "def main():\n    from . import helper\n    return helper.run()\n", encoding="utf-8"
    )
    (root / "src/demo_app/helper.py").write_text("def run(): return 0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[build-system]\n"
        f"requires = ['{backend.split('.')[0]}']\n"
        f"build-backend = '{backend}'\n"
        "[project]\nname = 'demo-app'\nversion = '1.0'\n"
        f"[project.scripts]\ndemo = '{target}'\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")


def _write_custom_source_root_project(root: Path, *, declare_helper: bool = False) -> None:
    (root / "lib/app").mkdir(parents=True, exist_ok=True)
    (root / "lib/app/__init__.py").write_text("", encoding="utf-8")
    (root / "lib/app/main.py").write_text(
        "import helper\n\ndef main():\n    return helper.value()\n", encoding="utf-8"
    )
    (root / "lib/helper.py").write_text("def value(): return 1\n", encoding="utf-8")
    helper = "py-modules = ['helper']\n" if declare_helper else ""
    (root / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools>=68']\n"
        "build-backend = 'setuptools.build_meta'\n"
        "[project]\nname = 'custom-root-app'\nversion = '1.0'\n"
        "[project.scripts]\ncustom-root = 'app.main:main'\n"
        "[tool.setuptools]\npackage-dir = {'' = 'lib'}\n"
        + helper
        + "[tool.setuptools.packages.find]\nwhere = ['lib']\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")


def _write_external_packaging_root_project(root: Path, *, installed_only: bool = False) -> None:
    shared = root.parent / f"{root.name}-shared"
    (root / "src/app").mkdir(parents=True)
    (shared / "helper").mkdir(parents=True)
    (root / "src/app/__init__.py").write_text("", encoding="utf-8")
    (root / "src/app/main.py").write_text(
        "def main():\n    from helper import value\n    return value()\n", encoding="utf-8"
    )
    (shared / "helper/__init__.py").write_text("def value(): return 1\n", encoding="utf-8")
    target = "installed_app.main:main" if installed_only else "app.main:main"
    (root / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='external-root-app'\nversion='1.0'\n"
        f"[project.scripts]\nexternal-root='{target}'\n"
        "[tool.setuptools.packages.find]\n"
        f"where=['src', '../{shared.name}']\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")


def test_import_promotion_uses_authoritative_custom_source_roots(tmp_path: Path) -> None:
    root = tmp_path / "custom-root"
    root.mkdir()
    _write_custom_source_root_project(root)

    assessment = assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )
    helper = next(item for item in assessment.file_inventory if item.path == "lib/helper.py")
    assert assessment.project.source_roots == ["lib"]
    assert any("Application source imports local module" in item.detail for item in helper.evidence)
    assert create_deployment_plan(assessment, repository_root=root).deployment_mode == "source"

    _write_custom_source_root_project(root, declare_helper=True)
    declared = assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )
    assert declared.project.py_modules == ["helper"]
    assert create_deployment_plan(declared, repository_root=root).deployment_mode == "package"


def test_module_file_resolution_searches_all_safe_configured_roots(tmp_path: Path) -> None:
    (tmp_path / "lib/foo").mkdir(parents=True)
    (tmp_path / "python/foo/bar").mkdir(parents=True)
    (tmp_path / "lib/helper.py").write_text("", encoding="utf-8")
    (tmp_path / "python/helper.py").write_text("", encoding="utf-8")
    (tmp_path / "lib/foo/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "python/foo/bar/__init__.py").write_text("", encoding="utf-8")
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "escape.py").write_text("", encoding="utf-8")

    assert [path.relative_to(tmp_path).as_posix() for path in _module_files(
        tmp_path, "helper", ["lib", "python", "missing", "../outside"]
    )] == ["lib/helper.py", "python/helper.py"]
    assert [path.relative_to(tmp_path).as_posix() for path in _module_files(
        tmp_path, "foo.bar", ["lib", "python"]
    )] == ["lib/foo/__init__.py", "python/foo/bar/__init__.py"]


def test_external_packaging_root_blocks_both_source_and_package_mode_contracts(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "external-source"
    _write_external_packaging_root_project(source_root)
    source_assessment = assess_repository(
        MaterializedRepository(root=source_root, source=str(source_root), source_kind="local")
    )
    source_plan = create_deployment_plan(source_assessment, repository_root=source_root)

    assert source_plan.deployment_mode == "source"
    assert "EXTERNAL_PACKAGING_ROOT_UNSUPPORTED" in source_plan.risk_gate.blocking_codes
    assert "EXTERNAL_PACKAGING_ROOT_UNSUPPORTED" in source_plan.readiness.blocker_codes

    package_root = tmp_path / "external-package"
    _write_external_packaging_root_project(package_root, installed_only=True)
    package_assessment = assess_repository(
        MaterializedRepository(root=package_root, source=str(package_root), source_kind="local")
    )
    package_plan = create_deployment_plan(package_assessment, repository_root=package_root)

    assert package_plan.deployment_mode == "package"
    assert "EXTERNAL_PACKAGING_ROOT_UNSUPPORTED" in package_plan.risk_gate.blocking_codes


@pytest.mark.parametrize("backend", ["hatchling.build", "poetry.core.masonry.api"])
def test_unresolved_backend_src_entrypoint_preserves_source_mode(
    tmp_path: Path, backend: str
) -> None:
    root = tmp_path / backend.replace(".", "-")
    _write_unresolved_backend_project(root, backend=backend, target="demo_app.main:main")

    assessment = assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=root)

    assert assessment.project.packages == []
    assert assessment.project.py_modules == []
    assert (plan.deployment_mode, plan.deployment_mode_condition) == (
        "source",
        "SOURCE_COMPATIBLE",
    )
    assert backend in plan.decisions[0].rationale


@pytest.mark.parametrize(
    "backend", ["hatchling.build", "poetry.core.masonry.api", "example.backend"]
)
def test_unresolved_backend_installed_entrypoint_is_blocked(
    tmp_path: Path, backend: str
) -> None:
    root = tmp_path / backend.replace(".", "-")
    _write_unresolved_backend_project(root, backend=backend, target="installed_app.main:main")

    plan = create_deployment_plan(
        assess_repository(MaterializedRepository(root=root, source=str(root), source_kind="local")),
        repository_root=root,
    )

    assert (plan.deployment_mode, plan.deployment_mode_condition) == (
        "package",
        "INSTALLED_PROJECT_REQUIRED",
    )
    assert plan.readiness.state == "BLOCKED"
    assert plan.readiness.blocker_codes == ["PACKAGING_SURFACE_UNRESOLVED"]


def test_complete_deployment_mode_decision_table(tmp_path: Path) -> None:
    cases = {
        "flat-source": dict(),
        "src-constrained": dict(layout="src", source_constraint=True),
        "src-install-oriented": dict(layout="src"),
        "mapped-installed-namespace": dict(
            mapped=True, target="installed_app.main:main"
        ),
        "mapped-conflict": dict(
            mapped=True,
            target="installed_app.main:main",
            source_constraint=True,
        ),
        "metadata-insufficient": dict(
            target="missing_app:main",
            buildable=False,
        ),
        "metadata-over-ast": dict(target="missing_app:main"),
    }
    results = {}
    for name, options in cases.items():
        root = tmp_path / name
        root.mkdir()
        _write_mode_project(root, **options)
        assessment = assess_repository(
            MaterializedRepository(root=root, source=str(root), source_kind="local")
        )
        results[name] = create_deployment_plan(assessment)

    assert (
        results["flat-source"].deployment_mode,
        results["flat-source"].deployment_mode_condition,
    ) == (
        "source",
        "SOURCE_COMPATIBLE",
    )
    assert (
        results["src-constrained"].deployment_mode,
        results["src-constrained"].deployment_mode_condition,
    ) == ("source", "SOURCE_COMPATIBLE")
    assert (
        results["src-install-oriented"].deployment_mode,
        results["src-install-oriented"].deployment_mode_condition,
    ) == ("package", "PACKAGE_PREFERRED")
    assert results["mapped-installed-namespace"].deployment_mode_condition == (
        "ENTRYPOINT_REQUIRES_PACKAGE_MODE"
    )
    conflict = results["mapped-conflict"]
    assert conflict.deployment_mode_condition == "DEPLOYMENT_MODE_CONFLICT"
    assert conflict.readiness.blocker_codes == ["DEPLOYMENT_MODE_CONFLICT"]
    insufficient = results["metadata-insufficient"]
    assert insufficient.deployment_mode_condition == "INSTALLED_PROJECT_REQUIRED"
    assert insufficient.readiness.blocker_codes == ["INSTALLED_PROJECT_REQUIRED"]
    metadata = results["metadata-over-ast"]
    assert metadata.entry_point.target == "missing_app:main"
    assert metadata.deployment_mode_condition == "ENTRYPOINT_REQUIRES_PACKAGE_MODE"
    assert all(plan.decisions[0].rationale for plan in results.values())


def test_repository_adjacent_resource_directory_constrains_deployment_mode(
    tmp_path: Path,
) -> None:
    """A conventional directory is a source-only constraint for every descendant."""

    source = tmp_path / "source-compatible"
    (source / "src/example_app").mkdir(parents=True)
    (source / "assets").mkdir()
    (source / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (source / "src/example_app/main.py").write_text(
        "def main(): return 0\n", encoding="utf-8"
    )
    (source / "assets/view.html").write_text("<main>view</main>\n", encoding="utf-8")
    (source / "assets2/ignored.html").parent.mkdir()
    (source / "assets2/ignored.html").write_text("ignored\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "directory-resource"
version = "1.0"
[project.scripts]
directory-resource = "example_app.main:main"
[tool.setuptools.packages.find]
where = ["src"]
""",
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(
        MaterializedRepository(root=source, source=str(source), source_kind="local")
    )
    roles = {item.path: item.role for item in assessment.file_inventory}
    plan = create_deployment_plan(assessment, repository_root=source)

    assert roles["assets/view.html"].value == "runtime_resource"
    assert roles["assets2/ignored.html"].value != "runtime_resource"
    assert (plan.deployment_mode, plan.deployment_mode_condition) == (
        "source",
        "SOURCE_COMPATIBLE",
    )


def test_repository_adjacent_resource_directory_conflicts_with_package_entrypoint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "package-required"
    (root / "src/example_app").mkdir(parents=True)
    (root / "assets").mkdir()
    (root / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (root / "src/example_app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (root / "assets/view.html").write_text("<main>view</main>\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "directory-resource"
version = "1.0"
[project.scripts]
directory-resource = "installed_app.main:main"
[tool.setuptools.packages.find]
where = ["src"]
""",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    plan = create_deployment_plan(
        assess_repository(MaterializedRepository(root=root, source=str(root), source_kind="local")),
        repository_root=root,
    )

    assert (plan.deployment_mode, plan.deployment_mode_condition) == (
        "package",
        "DEPLOYMENT_MODE_CONFLICT",
    )
    assert "assets/view.html" in plan.readiness.blockers[0]


def test_wheel_backed_package_data_resource_does_not_force_source_mode(tmp_path: Path) -> None:
    root = tmp_path / "wheel-backed"
    (root / "src/example_app/templates").mkdir(parents=True)
    (root / "src/example_app/__init__.py").write_text("", encoding="utf-8")
    (root / "src/example_app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (root / "src/example_app/templates/view.html").write_text("view\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "wheel-backed"
version = "1.0"
[project.scripts]
wheel-backed = "example_app.main:main"
[tool.setuptools.packages.find]
where = ["src"]
[tool.setuptools.package-data]
example_app = ["templates/*.html"]
""",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    plan = create_deployment_plan(
        assess_repository(MaterializedRepository(root=root, source=str(root), source_kind="local")),
        repository_root=root,
    )

    assert (plan.deployment_mode, plan.deployment_mode_condition) == (
        "package",
        "PACKAGE_PREFERRED",
    )


@pytest.mark.parametrize(
    ("target", "py_modules", "expected"),
    [
        ("app.main:main", False, ("source", "SOURCE_COMPATIBLE")),
        ("installed_app.main:main", False, ("package", "DEPLOYMENT_MODE_CONFLICT")),
        ("app.main:main", True, ("package", "PACKAGE_PREFERRED")),
    ],
)
def test_promoted_standalone_source_requires_authoritative_wheel_membership(
    tmp_path: Path,
    target: str,
    py_modules: bool,
    expected: tuple[str, str],
) -> None:
    root = tmp_path / "standalone-helper"
    (root / "src/app").mkdir(parents=True)
    (root / "src/app/__init__.py").write_text("", encoding="utf-8")
    (root / "src/app/main.py").write_text(
        "import helper\ndef main(): return helper.VALUE\n", encoding="utf-8"
    )
    (root / "src/helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    py_modules_text = "[tool.setuptools]\npy-modules = [\"helper\"]\n" if py_modules else ""
    (root / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "standalone-helper"
version = "1.0"
[project.scripts]
standalone-helper = """
        + repr(target)
        + "\n"
        + py_modules_text
        + """[tool.setuptools.packages.find]
where = ["src"]
namespaces = false
""",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    assessment = assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )
    plan = create_deployment_plan(assessment, repository_root=root)

    assert any(
        item.path == "src/helper.py" and item.role.value == "application_source"
        for item in assessment.file_inventory
    )
    assert (plan.deployment_mode, plan.deployment_mode_condition) == expected
    if py_modules:
        assert assessment.project.py_modules == ["helper"]
        assert not any("src/helper.py" in item for item in plan.readiness.blockers)
    else:
        assert any("src/helper.py" in item for item in plan.readiness.blockers) == (
            expected[1] == "DEPLOYMENT_MODE_CONFLICT"
        )


def test_target_plan_selects_source_gui_and_external_environment() -> None:
    plan = create_deployment_plan(_assess())

    assert plan.deployment_mode == "source"
    assert plan.entry_point.kind == "gui"
    assert plan.entry_point.declared_group == "console_scripts"
    assert plan.runtime.backend == "uv_managed"
    assert plan.runtime.python_version == "3.12"
    assert plan.runtime.uv_version == UV_VERSION
    assert plan.runtime.paths.environment_path.endswith(r"apps\target-app\env")
    assert plan.runtime.environment_variables["UV_PROJECT_ENVIRONMENT"].endswith(
        r"apps\target-app\env"
    )
    assert plan.runtime.environment_variables["UV_PYTHON_NO_REGISTRY"] == "1"
    assert "--locked" in plan.runtime.sync_command.arguments
    assert "--no-build" in plan.runtime.sync_command.arguments
    assert "--no-install-project" in plan.runtime.sync_command.arguments
    assert plan.runtime.environment_variables["PYTHONPATH"] == r"%PROJECT_ROOT%\src"
    assert plan.lockfile.status == "developer_generation_required"
    assert plan.readiness.state == "BLOCKED_PENDING_LOCKFILE"
    assert plan.risk_gate.outcome == "allow_with_warnings"
    assert plan.writes.requires_project_write_probe
    api_key = next(item for item in plan.configuration if item.name == "OPENAI_API_KEY")
    assert api_key.supply_strategy == "existing_application_workflow"


def test_selected_entry_point_retains_group_from_exact_assessment_entry(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "duplicate-entry"
version = "1.0"
[project.scripts]
tool = "app.console:main"
[project.gui-scripts]
tool = "app.gui:main"
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")

    plan = create_deployment_plan(
        assess_repository(
            MaterializedRepository(root=tmp_path, source=str(tmp_path), source_kind="local")
        )
    )

    assert plan.entry_point is not None
    assert (plan.entry_point.target, plan.entry_point.declared_group) == (
        "app.gui:main",
        "gui_scripts",
    )


def test_policy_uses_next_supported_python_when_312_is_rejected() -> None:
    assessment = _assess()
    assessment.python.requires_python = ">=3.13"

    plan = create_deployment_plan(assessment)

    assert plan.runtime.python_version == "3.13"


def test_policy_skips_patch_unprovable_candidate_for_minor_only_runtime() -> None:
    assessment = _assess()
    assessment.python.requires_python = ">=3.12.1"

    plan = create_deployment_plan(assessment)

    candidate_312 = next(item for item in plan.python_candidates if item.version == "3.12")
    assert candidate_312.compatibility == "unverified"
    assert not candidate_312.satisfies_requires_python
    assert plan.runtime.python_version == "3.13"


def test_policy_accepts_exact_exclusion_outside_selected_minor() -> None:
    assessment = _assess()
    assessment.python.requires_python = ">=3.9,!=3.9.0"

    plan = create_deployment_plan(assessment)

    candidate_312 = next(item for item in plan.python_candidates if item.version == "3.12")
    assert candidate_312.satisfies_requires_python
    assert candidate_312.compatibility != "incompatible"
    assert plan.runtime.python_version == "3.12"


def test_blocking_assessment_gates_generation_policy() -> None:
    assessment = _assess()
    assessment.rating = SuitabilityRating.RED
    assessment.risks.append(
        RiskFinding(
            code="EXTERNAL_RUNTIME_BLOCK",
            title="External runtime blocks generic deployment",
            severity=RiskSeverity.BLOCKING,
            status=FindingStatus.DETECTED,
            description="A required external runtime is unavailable.",
        )
    )

    plan = create_deployment_plan(assessment)

    assert plan.risk_gate.outcome == "block"
    assert plan.risk_gate.blocking_codes == ["EXTERNAL_RUNTIME_BLOCK"]


def test_uv_backend_has_pinned_hash_and_scoped_paths() -> None:
    runtime = UvManagedBackend().build_plan("sample-app", "3.12", "x86_64")

    assert runtime.bootstrap_artifact.sha256 == (
        "4c4d49d8738847d9b71ba319e49a5688c93eac0fe6204b1df24e98528dddf39a"
    )
    assert runtime.bootstrap_artifact.url.endswith("uv-x86_64-pc-windows-msvc.zip")
    assert runtime.paths.application_root.endswith(r"apps\sample-app")
    assert "--no-bin" in runtime.provision_command.arguments


def test_package_plan_syncs_dependencies_then_installs_prebuilt_wheel() -> None:
    plan = create_deployment_plan(_assess("simple_cli"))

    assert plan.deployment_mode == "package"
    assert "--no-install-project" in plan.runtime.sync_command.arguments
    assert plan.runtime.application_install_command is not None
    assert "%APPLICATION_WHEEL%" in plan.runtime.application_install_command.arguments
    assert "PYTHONPATH" not in plan.runtime.environment_variables


def test_safe_application_id_is_bounded_and_path_safe() -> None:
    assert safe_application_id("Geo Map Explanation Extractor") == (
        "geo-map-explanation-extractor"
    )
    assert safe_application_id("../../") == "python-application"
    assert len(safe_application_id("x" * 100)) == 64


def test_online_inspection_records_context_and_matching_wheels() -> None:
    dependency = DependencyAssessment(
        distribution_name="demo",
        declared_constraint=">=1",
        group="runtime",
    )

    def fetcher(_url: str):
        return {
            "releases": {
                "1.2.0": [
                    {
                        "filename": "demo-1.2.0-py3-none-any.whl",
                        "requires_python": ">=3.9",
                    },
                    {"filename": "demo-1.2.0.tar.gz", "requires_python": ">=3.9"},
                ],
                "2.0.0": [
                    {
                        "filename": "demo-2.0.0-py3-none-any.whl",
                        "requires_python": ">=3.13",
                    }
                ],
            }
        }

    result = inspect_dependency_wheels(
        [dependency], ["3.12", "3.13"], "x86_64", fetcher=fetcher
    )

    assert result.context.index_url == "https://pypi.org/pypi"
    assert result.context.python_targets == ["3.12", "3.13"]
    assert all(item.wheel_available for item in result.dependencies)
    assert [item.resolved_version for item in result.dependencies] == ["1.2.0", "2.0.0"]


def test_online_inspection_includes_selected_windows_extra_and_skips_linux_marker() -> None:
    dependencies = [
        DependencyAssessment(
            distribution_name="pywebview",
            declared_constraint=">=6,<7",
            group="map",
            environment_marker="sys_platform == 'win32'",
        ),
        DependencyAssessment(
            distribution_name="linux-only",
            declared_constraint=">=1",
            group="map",
            environment_marker="sys_platform == 'linux'",
        ),
    ]

    def fetcher(url: str):
        name = url.rstrip("/").split("/")[-2]
        return {
            "releases": {
                "6.2.1" if name == "pywebview" else "1.0.0": [
                    {
                        "filename": f"{name}-6.2.1-py3-none-any.whl",
                        "requires_python": ">=3.10",
                    }
                ]
            }
        }

    result = inspect_dependency_wheels(
        dependencies, ["3.12"], "x86_64", fetcher=fetcher
    )

    assert [item.distribution_name for item in result.dependencies] == ["pywebview"]


def test_plan_markdown_explains_locked_sync_bootstrap_and_write_policy() -> None:
    rendered = render_deployment_plan_markdown(create_deployment_plan(_assess()))

    assert "# Deployment plan" in rendered
    assert "`source`" in rendered
    assert "--locked" in rendered
    assert "PowerShell allowed: `false`" in rendered
    assert "`curl.exe`: Download the pinned official uv archive" in rendered
    assert "## Windows platform applicability" in rendered
    assert "Project write probe required: `true`" in rendered
    assert "OPENAI_API_KEY" in rendered


def test_optional_extra_is_recommended_but_requires_explicit_selection() -> None:
    assessment = _assess("optional_map_app")
    plan = create_deployment_plan(
        assessment,
        repository_root=FIXTURES / "optional_map_app",
    )

    map_extra = next(item for item in plan.extras if item.name == "map")
    dev_extra = next(item for item in plan.extras if item.name == "dev")
    assert map_extra.recommended
    assert not map_extra.selected
    assert not dev_extra.selected
    assert "--extra" not in plan.runtime.sync_command.arguments


def test_selected_extra_propagates_and_excludes_dev() -> None:
    assessment = _assess("optional_map_app")
    plan = create_deployment_plan(
        assessment,
        selected_extras=["map"],
        repository_root=FIXTURES / "optional_map_app",
    )

    assert plan.runtime.selected_extras == ["map"]
    arguments = plan.runtime.sync_command.arguments
    assert "--no-dev" in arguments
    assert arguments[arguments.index("--extra") : arguments.index("--extra") + 2] == [
        "--extra",
        "map",
    ]
    assert arguments[-1] == "--no-install-project"
    assert "dev" not in plan.runtime.selected_extras
    assert plan.selected_extras_fingerprint


def test_unknown_selected_extra_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown optional dependency extra"):
        create_deployment_plan(_assess("optional_map_app"), selected_extras=["missing"])


@pytest.mark.parametrize("requested", ["Foo_Bar", "foo-bar", "foo.bar"])
def test_selected_extra_resolves_to_authoritative_declared_group(requested: str) -> None:
    assessment = _assess("optional_map_app")
    dependency = DependencyAssessment(
        distribution_name="requests",
        declared_constraint=">=2",
        group="Foo_Bar",
        import_names=["requests"],
    )
    assessment.project.optional_dependency_groups = {"Foo_Bar": ["requests>=2"]}
    assessment.dependencies = [dependency]

    plan = create_deployment_plan(assessment, selected_extras=[requested])

    assert plan.runtime.selected_extras == ["Foo_Bar"]
    assert plan.extras[0].selected
    assert "Foo_Bar" in plan.runtime.sync_command.arguments


def test_canonically_colliding_optional_extra_declarations_fail() -> None:
    assessment = _assess("optional_map_app")
    assessment.project.optional_dependency_groups = {"Foo_Bar": [], "foo-bar": []}

    with pytest.raises(ValueError, match="collide after PEP-685"):
        create_deployment_plan(assessment, selected_extras=["foo-bar"])


def test_windows_environment_markers_are_applied() -> None:
    assert marker_applies("sys_platform == 'win32'", "3.12", "x86_64", extra="map")
    assert not marker_applies("sys_platform == 'linux'", "3.12", "x86_64", extra="map")


@pytest.mark.parametrize(
    ("constraint", "expected"),
    [
        (">=3.12", MinorPythonCompatibility.COMPATIBLE),
        ("<3.13", MinorPythonCompatibility.COMPATIBLE),
        (">=3.13", MinorPythonCompatibility.INCOMPATIBLE),
        ("<3.12", MinorPythonCompatibility.INCOMPATIBLE),
        ("==3.12.*", MinorPythonCompatibility.COMPATIBLE),
        (">=3.12.1", MinorPythonCompatibility.UNPROVABLE),
        ("<3.12.1", MinorPythonCompatibility.UNPROVABLE),
        ("==3.12.0", MinorPythonCompatibility.UNPROVABLE),
        ("!=3.9.0", MinorPythonCompatibility.COMPATIBLE),
        ("!=3.11.99", MinorPythonCompatibility.COMPATIBLE),
        ("!=3.13.0", MinorPythonCompatibility.COMPATIBLE),
        ("!=3.14.1", MinorPythonCompatibility.COMPATIBLE),
        ("!=3.12.5", MinorPythonCompatibility.UNPROVABLE),
        (">=3.9,!=3.9.0", MinorPythonCompatibility.COMPATIBLE),
        (">=3.9,!=3.12.1", MinorPythonCompatibility.UNPROVABLE),
        (">=3.13,!=3.9.0", MinorPythonCompatibility.INCOMPATIBLE),
        ("~=3.12.1", MinorPythonCompatibility.UNPROVABLE),
    ],
)
def test_minor_python_compatibility_does_not_fabricate_patch_precision(
    constraint: str, expected: MinorPythonCompatibility
) -> None:
    assert minor_python_compatibility("3.12", constraint) == expected


@pytest.mark.parametrize("selected", ["feature_one", "feature-one", "feature.one"])
def test_target_marker_environment_normalizes_selected_extra(selected: str) -> None:
    assert (
        target_marker_applicability(
            'extra == "feature_one"', "3.12", "x86_64", extra=selected
        )
        == TargetMarkerApplicability.APPLIES
    )
    assert target_marker_environment("3.12", "x86_64", extra=selected)["extra"] == "feature-one"
    assert (
        target_marker_applicability(
            'extra == "feature_one"', "3.12", "x86_64", extra="other"
        )
        == TargetMarkerApplicability.DOES_NOT_APPLY
    )


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ('python_version >= "3.12"', TargetMarkerApplicability.APPLIES),
        ('python_version < "3.13"', TargetMarkerApplicability.APPLIES),
        ('python_version >= "3.13"', TargetMarkerApplicability.DOES_NOT_APPLY),
        ('python_full_version >= "3.12.1"', TargetMarkerApplicability.UNPROVABLE),
        ('python_full_version == "3.12.0"', TargetMarkerApplicability.UNPROVABLE),
        ('implementation_version >= "3.12.1"', TargetMarkerApplicability.UNPROVABLE),
    ],
)
def test_target_marker_applicability_does_not_fabricate_python_patch(
    marker: str, expected: TargetMarkerApplicability
) -> None:
    assert target_marker_applicability(marker, "3.12", "x86_64") == expected


def test_patch_sensitive_markers_are_conservative_for_lock_traversal() -> None:
    """A possibly applicable lock edge must not vanish because 3.12.x is unknown."""

    assert marker_applies('python_full_version >= "3.12.1"', "3.12", "x86_64")
    with pytest.raises(TargetMarkerEnvironmentError, match="patch-sensitive"):
        target_marker_applies('implementation_version >= "3.12.1"', "3.12", "x86_64")
    environment = target_marker_environment("3.12", "x86_64")
    assert "python_full_version" not in environment
    assert "implementation_version" not in environment


def test_lock_graph_retains_dependency_edge_with_patch_sensitive_marker(
    tmp_path: Path,
) -> None:
    (tmp_path / "uv.lock").write_text(
        """version = 1
revision = 3
[[package]]
name = "example"
version = "1.0"
source = { virtual = "." }
dependencies = [{ name = "helper", marker = "python_full_version >= '3.12.1'" }]
[[package]]
name = "helper"
version = "1.0"
wheels = [{ url = "https://example.invalid/helper-1.0-py3-none-any.whl" }]
""",
        encoding="utf-8",
    )

    graph = inspect_uv_lock(tmp_path, "example", "3.12", "x86_64", [])

    edge = next(item for item in graph.edges if item.to_package == "helper")
    assert edge.applicable
    assert any(item.name == "helper" for item in graph.dependencies)


def test_lock_graph_reports_pywebview_proxy_tools_source_only_chain() -> None:
    graph = inspect_uv_lock(
        FIXTURES / "optional_map_app",
        "optional-map-app",
        "3.12",
        "x86_64",
        ["map"],
    )

    proxy = next(item for item in graph.dependencies if item.name == "proxy-tools")
    assert not proxy.direct
    assert proxy.selected_extra == "map"
    assert proxy.dependency_chain == ["optional-map-app", "pywebview", "proxy-tools"]
    assert proxy.artifact.policy == "developer_wheel_required"
    assert graph.artifact_requirements[0].package == "proxy-tools"


def test_source_only_locked_dependency_blocks_readiness_for_developer_artifact() -> None:
    plan = create_deployment_plan(
        _assess("optional_map_app"),
        selected_extras=["map"],
        repository_root=FIXTURES / "optional_map_app",
    )

    assert plan.lockfile.status == "present_unverified"
    assert plan.readiness.state == "BLOCKED_PENDING_DEVELOPER_ARTIFACT"
    assert any("proxy-tools==0.1.0" in item for item in plan.readiness.blockers)
    assert any(
        command.arguments == ["lock", "--check"]
        for command in plan.lockfile.developer_commands
    )


def test_selected_map_feature_models_webview2_as_feature_runtime() -> None:
    plan = create_deployment_plan(
        _assess("optional_map_app"),
        selected_extras=["map"],
        repository_root=FIXTURES / "optional_map_app",
    )

    runtime = next(item for item in plan.external_runtimes if "WebView2" in item.name)
    assert runtime.feature == "map"
    assert runtime.required_for_feature
    assert not runtime.required_at_launch
    assert runtime.automatic_installation_policy == "never_automatic"


def test_windows_plan_prohibits_powershell_and_models_cmd_bootstrap() -> None:
    plan = create_deployment_plan(_assess())

    assert not plan.shell_policy.powershell_allowed
    assert set(plan.shell_policy.prohibited_executables) == {"powershell.exe", "pwsh.exe"}
    assert plan.bootstrap.preferred_mode == "bundled_uv"
    assert {item.mode for item in plan.bootstrap.modes} >= {"bundled_uv", "online_cmd"}
    online = next(item for item in plan.bootstrap.modes if item.mode == "online_cmd")
    assert {item.executable for item in online.required_host_tools} == {
        "curl.exe",
        "tar.exe",
        "certutil.exe",
    }
    commands = [plan.runtime.provision_command, plan.runtime.sync_command]
    if plan.runtime.application_install_command:
        commands.append(plan.runtime.application_install_command)
    planned_text = " ".join(
        " ".join([command.executable, *command.arguments, command.working_directory or ""])
        for command in commands
    ).lower()
    assert ".ps1" not in planned_text
    assert "powershell.exe" not in planned_text
    assert "pwsh.exe" not in planned_text


def test_secret_environment_value_is_never_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-never-appear-in-plan")

    serialized = create_deployment_plan(_assess()).model_dump_json()

    assert "must-never-appear-in-plan" not in serialized


def test_src_and_flat_source_layouts_set_distinct_python_paths() -> None:
    src_plan = create_deployment_plan(_assess("target_app"))
    flat_plan = create_deployment_plan(
        _assess("optional_map_app"),
        selected_extras=["map"],
        repository_root=FIXTURES / "optional_map_app",
    )

    assert src_plan.runtime.environment_variables["PYTHONPATH"] == r"%PROJECT_ROOT%\src"
    assert flat_plan.runtime.environment_variables["PYTHONPATH"] == "%PROJECT_ROOT%"


def test_platform_specific_findings_are_filtered_for_windows() -> None:
    treatments = windows_finding_treatments(
        [
            RuntimeRequirement(
                category="external_executable",
                name="xdg-open",
                description="Linux launcher",
                status=FindingStatus.DETECTED,
                platforms=["linux"],
            ),
            RuntimeRequirement(
                category="external_launcher",
                name="os.startfile",
                description="Windows launcher",
                status=FindingStatus.DETECTED,
                platforms=["windows"],
            ),
        ]
    )

    assert treatments[0].decision == "ignored_for_windows"
    assert treatments[1].decision == "applicable"
