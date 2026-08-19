"""Command-line interface for the deployment lifecycle."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import (
    RepositoryLoadError,
    materialize_repository,
)
from python_deployment_builder.reporting import write_assessment_reports


def application_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized[:64] or "python-application"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdbuilder",
        description="Analyze, plan, generate, and validate no-admin Python deployments.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    assess = commands.add_parser("assess", help="statically assess a repository")
    assess.add_argument("repository", help="local path or public GitHub repository URL")
    assess.add_argument(
        "--output-dir",
        type=Path,
        help="report directory (default: ./pdbuilder-output/<application-id>)",
    )
    for name, help_text in (
        ("plan", "plan deployment policy from an assessment (Milestone 2)"),
        ("generate", "generate an end-user deployment kit (Milestone 3)"),
        ("validate", "validate a generated deployment (Milestone 4)"),
        ("all", "run the complete lifecycle as implemented"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("repository")
        if name in {"generate", "validate"}:
            command.add_argument("--dry-run", action="store_true")
    return parser


def run_assess(repository_value: str, output_dir: Path | None) -> int:
    with materialize_repository(repository_value) as repository:
        assessment = assess_repository(repository)
        chosen_output = output_dir or (
            Path.cwd()
            / "pdbuilder-output"
            / application_id(assessment.project.distribution_name or repository.root.name)
        )
        json_path, markdown_path = write_assessment_reports(assessment, chosen_output.resolve())
    print(f"Assessment: {assessment.rating.value} - {assessment.rating_summary}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "assess":
            return run_assess(arguments.repository, arguments.output_dir)
        parser.error(
            f"'{arguments.command}' is part of the stable CLI shape but is not implemented "
            "until its scheduled milestone."
        )
    except RepositoryLoadError as exc:
        print(f"Repository error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Assessment failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
