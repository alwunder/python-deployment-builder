"""Persist stable JSON and companion Markdown reports."""

from __future__ import annotations

from pathlib import Path

from python_deployment_builder.models import (
    DeploymentPlan,
    RepositoryAssessment,
    ValidationReport,
)
from python_deployment_builder.reporting.markdown import (
    render_assessment_markdown,
    render_deployment_plan_markdown,
    render_validation_markdown,
)


def write_assessment_reports(
    assessment: RepositoryAssessment, output_directory: Path
) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "assessment.json"
    markdown_path = output_directory / "assessment.md"
    json_path.write_text(
        assessment.model_dump_json(indent=2, exclude_none=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_assessment_markdown(assessment), encoding="utf-8")
    return json_path, markdown_path


def write_deployment_plan_reports(
    plan: DeploymentPlan, output_directory: Path
) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "deployment-plan.json"
    markdown_path = output_directory / "deployment-plan.md"
    json_path.write_text(
        plan.model_dump_json(indent=2, exclude_none=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_deployment_plan_markdown(plan), encoding="utf-8")
    return json_path, markdown_path


def write_validation_reports(
    report: ValidationReport, output_directory: Path
) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "validation-report.json"
    markdown_path = output_directory / "validation-report.md"
    json_path.write_text(
        report.model_dump_json(indent=2, exclude_none=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_validation_markdown(report), encoding="utf-8")
    return json_path, markdown_path
