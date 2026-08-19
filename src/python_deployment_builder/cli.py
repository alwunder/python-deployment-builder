"""Command-line interface for the deployment lifecycle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import (
    RepositoryLoadError,
    materialize_repository,
)
from python_deployment_builder.planning import create_deployment_plan
from python_deployment_builder.planning.policies import safe_application_id
from python_deployment_builder.reporting import (
    write_assessment_reports,
    write_deployment_plan_reports,
)


def application_id(value: str) -> str:
    """Backward-compatible public helper used by early integrations."""

    return safe_application_id(value)


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
    plan = commands.add_parser("plan", help="plan deployment policy from static assessment")
    plan.add_argument("repository", help="local path or public GitHub repository URL")
    plan.add_argument(
        "--output-dir",
        type=Path,
        help="report directory (default: ./pdbuilder-output/<application-id>)",
    )
    plan.add_argument(
        "--online",
        action="store_true",
        help="query the PyPI JSON API for Windows wheel evidence; never builds packages",
    )
    plan.add_argument(
        "--architecture",
        choices=("x86_64", "arm64"),
        default="x86_64",
        help="target Windows architecture (default: x86_64)",
    )
    for name, help_text in (
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


def run_plan(
    repository_value: str,
    output_dir: Path | None,
    *,
    online: bool,
    architecture: str,
) -> int:
    with materialize_repository(repository_value) as repository:
        assessment = assess_repository(repository)
        chosen_output = output_dir or (
            Path.cwd()
            / "pdbuilder-output"
            / application_id(assessment.project.distribution_name or repository.root.name)
        )
        plan = create_deployment_plan(
            assessment,
            architecture=architecture,
            online=online,
        )
        json_path, markdown_path = write_deployment_plan_reports(plan, chosen_output.resolve())
    print(
        f"Deployment plan: {plan.risk_gate.outcome.replace('_', ' ')} - "
        f"{plan.deployment_mode} / Python {plan.runtime.python_version} / {plan.runtime.backend}"
    )
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 1 if plan.risk_gate.outcome == "block" else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "assess":
            return run_assess(arguments.repository, arguments.output_dir)
        if arguments.command == "plan":
            return run_plan(
                arguments.repository,
                arguments.output_dir,
                online=arguments.online,
                architecture=arguments.architecture,
            )
        parser.error(
            f"'{arguments.command}' is part of the stable CLI shape but is not implemented "
            "until its scheduled milestone."
        )
    except RepositoryLoadError as exc:
        print(f"Repository error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Command failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
