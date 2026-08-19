from pathlib import Path

from python_deployment_builder.analysis.assessor import assess_repository
from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.backends.uv_managed import UV_VERSION, UvManagedBackend
from python_deployment_builder.models import (
    DependencyAssessment,
    FindingStatus,
    RiskFinding,
    RiskSeverity,
    SuitabilityRating,
)
from python_deployment_builder.planning.index import inspect_dependency_wheels
from python_deployment_builder.planning.planner import create_deployment_plan
from python_deployment_builder.planning.policies import safe_application_id
from python_deployment_builder.reporting.markdown import render_deployment_plan_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _assess(name: str = "target_app"):
    root = FIXTURES / name
    return assess_repository(
        MaterializedRepository(root=root, source=str(root), source_kind="local")
    )


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
    assert "--frozen" in plan.runtime.sync_command.arguments
    assert "--no-build" in plan.runtime.sync_command.arguments
    assert "--no-install-project" in plan.runtime.sync_command.arguments
    assert plan.runtime.environment_variables["PYTHONPATH"] == r"%PROJECT_ROOT%\src"
    assert plan.lockfile.status == "developer_generation_required"
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


def test_plan_markdown_explains_frozen_sync_and_write_policy() -> None:
    rendered = render_deployment_plan_markdown(create_deployment_plan(_assess()))

    assert "# Deployment plan" in rendered
    assert "`source`" in rendered
    assert "--frozen" in rendered
    assert "Project write probe required: `true`" in rendered
    assert "OPENAI_API_KEY" in rendered
