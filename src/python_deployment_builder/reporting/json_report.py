"""Persist stable JSON and companion Markdown reports."""

from __future__ import annotations

from pathlib import Path

from python_deployment_builder.models import RepositoryAssessment
from python_deployment_builder.reporting.markdown import render_assessment_markdown


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
