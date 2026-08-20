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
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import generate_deployment_kit
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
    plan.add_argument(
        "--extra",
        action="append",
        default=[],
        help="select one optional application feature; repeat for multiple extras",
    )
    generate = commands.add_parser("generate", help="generate an end-user deployment kit")
    generate.add_argument("repository", help="local path or public GitHub repository URL")
    generate.add_argument(
        "--output-dir",
        type=Path,
        help="staging directory (default: ./pdbuilder-output/<application-id>/deployment-kit)",
    )
    generate.add_argument("--online", action="store_true", help="include online wheel evidence")
    generate.add_argument(
        "--architecture",
        choices=("x86_64", "arm64"),
        default="x86_64",
        help="target Windows architecture (default: x86_64)",
    )
    generate.add_argument(
        "--extra", action="append", default=[], help="select an optional application feature"
    )
    generate.add_argument(
        "--bootstrap",
        choices=("bundled_uv", "online_cmd"),
        default="bundled_uv",
        help="end-user uv bootstrap strategy (default: bundled_uv)",
    )
    generate.add_argument(
        "--system-certs",
        action="store_true",
        help="make uv use the Windows certificate store for corporate trust roots",
    )
    generate.add_argument(
        "--prepare-lock",
        action="store_true",
        help="explicitly authorize local uv.lock creation when missing",
    )
    generate.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="DISTRIBUTION=WHEEL",
        help="supply an exact approved wheel for a typed developer-artifact requirement",
    )
    generate.add_argument("--dry-run", action="store_true")
    validate = commands.add_parser(
        "validate", help="validate a generated deployment (Milestone 4)"
    )
    validate.add_argument("repository")
    validate.add_argument("--dry-run", action="store_true")
    all_command = commands.add_parser("all", help="run the complete lifecycle as implemented")
    all_command.add_argument("repository")
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
    selected_extras: list[str],
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
            selected_extras=selected_extras,
            repository_root=repository.root,
        )
        json_path, markdown_path = write_deployment_plan_reports(plan, chosen_output.resolve())
    print(
        f"Deployment plan: {plan.risk_gate.outcome.replace('_', ' ')} - "
        f"{plan.deployment_mode} / Python {plan.runtime.python_version} / {plan.runtime.backend} / "
        f"readiness {plan.readiness.state}"
    )
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 1 if plan.risk_gate.outcome == "block" else 0


def run_generate(
    repository_value: str,
    output_dir: Path | None,
    *,
    online: bool,
    architecture: str,
    selected_extras: list[str],
    bootstrap_mode: str,
    system_certs: bool,
    prepare_lock: bool,
    artifact_values: list[str],
    dry_run: bool,
) -> int:
    with materialize_repository(repository_value) as repository:
        if output_dir is None:
            assessment = assess_repository(repository)
            app_id = application_id(
                assessment.project.distribution_name or repository.root.name
            )
            output_dir = Path.cwd() / "pdbuilder-output" / app_id / "deployment-kit"
            try:
                output_dir.resolve().relative_to(repository.root.resolve())
            except ValueError:
                pass
            else:
                # A default staging directory must not recursively contain the
                # repository it is about to copy. Keep it beside a local target
                # when the command is run from that target's working tree.
                output_dir = (
                    repository.root.resolve().parent
                    / "pdbuilder-output"
                    / app_id
                    / "deployment-kit"
                )
        result = generate_deployment_kit(
            repository,
            output_dir,
            architecture=architecture,
            online=online,
            selected_extras=selected_extras,
            prepare_lock=prepare_lock,
            bootstrap_mode=bootstrap_mode,
            system_certs=system_certs,
            artifact_values=artifact_values,
            dry_run=dry_run,
        )
    preview = result.preview
    print(f"Deployment readiness: {preview.readiness_before}")
    print(f"Bootstrap: {preview.bootstrap_mode}")
    print(f"System certificates: {'enabled' if preview.system_certs else 'disabled'}")
    print("Developer preparation:")
    for action in preview.developer_actions:
        print(f"  - {action}")
    print(f"Files to create: {len(preview.files_to_create)}")
    for path in preview.files_to_create:
        print(f"  + {path}")
    print(f"Files to replace: {len(preview.files_to_replace)}")
    for path in preview.files_to_replace:
        print(f"  ~ {path}")
    if preview.collisions:
        print("Collisions:")
        for path in preview.collisions:
            print(f"  ! {path}")
    print("Runtime paths:")
    print(f"  environment: {preview.runtime_paths.environment_path}")
    print(f"  logs: {preview.runtime_paths.logs_path}")
    print("Launcher behavior:")
    for behavior in preview.launcher_behavior:
        print(f"  - {behavior}")
    if result.generated:
        print(f"Deployment readiness after preparation: {preview.readiness_after}")
        if preview.repository_files_changed:
            print("Repository files changed by explicit preparation:")
            for path in preview.repository_files_changed:
                print(f"  * {path}")
        print(f"Generated deployment kit: {result.output_directory}")
        print(f"Deployment fingerprint: {result.manifest.deployment_fingerprint}")
    else:
        print("Dry run only; no downloads, commands, repository changes, or files were made.")
    return 2 if preview.collisions else 0


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
                selected_extras=arguments.extra,
            )
        if arguments.command == "generate":
            return run_generate(
                arguments.repository,
                arguments.output_dir,
                online=arguments.online,
                architecture=arguments.architecture,
                selected_extras=arguments.extra,
                bootstrap_mode=arguments.bootstrap,
                system_certs=arguments.system_certs,
                prepare_lock=arguments.prepare_lock,
                artifact_values=arguments.artifact,
                dry_run=arguments.dry_run,
            )
        parser.error(
            f"'{arguments.command}' is part of the stable CLI shape but is not implemented "
            "until its scheduled milestone."
        )
    except RepositoryLoadError as exc:
        print(f"Repository error: {exc}", file=sys.stderr)
        return 2
    except PreparationError as exc:
        print(f"Generation stopped: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Command failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
