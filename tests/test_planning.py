from pathlib import Path

import pytest

from python_deployment_builder.analysis.assessor import assess_repository
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
from python_deployment_builder.planning.index import inspect_dependency_wheels, marker_applies
from python_deployment_builder.planning.lockfile import inspect_uv_lock
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.planning.platforms import windows_finding_treatments
from python_deployment_builder.planning.policies import safe_application_id
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
    source = root / ("code" if mapped else "src" if layout == "src" else ".")
    source.mkdir(parents=True, exist_ok=True)
    module = source / ("main.py" if mapped else "sample_app.py")
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


def test_target_plan_selects_source_gui_and_external_environment() -> None:
    plan = create_deployment_plan(_assess())

    assert plan.deployment_mode == "source"
    assert plan.entry_point.kind == "gui"
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


def test_policy_uses_next_supported_python_when_312_is_rejected() -> None:
    assessment = _assess()
    assessment.python.requires_python = ">=3.13"

    plan = create_deployment_plan(assessment)

    assert plan.runtime.python_version == "3.13"


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


def test_windows_environment_markers_are_applied() -> None:
    assert marker_applies("sys_platform == 'win32'", "3.12", "x86_64", extra="map")
    assert not marker_applies("sys_platform == 'linux'", "3.12", "x86_64", extra="map")


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
