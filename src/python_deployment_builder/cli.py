"""Command-line interface for the deployment lifecycle."""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from python_deployment_builder import __version__
from python_deployment_builder.analysis import assess_repository
from python_deployment_builder.analysis.repository import (
    RepositoryLoadError,
    materialize_repository,
)
from python_deployment_builder.configuration import resolve_workflow_settings
from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.packaging import package_deployment_kit
from python_deployment_builder.planning import create_deployment_plan
from python_deployment_builder.planning.policies import safe_application_id
from python_deployment_builder.reporting import (
    write_assessment_reports,
    write_deployment_plan_reports,
    write_validation_reports,
)
from python_deployment_builder.validation import validate_runtime_kit, validate_static_kit


def application_id(value: str) -> str:
    """Backward-compatible public helper used by early integrations."""

    return safe_application_id(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdbuilder",
        description=(
            "Analyze, plan, generate, validate, and package no-admin Python deployments."
        ),
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
        default=None,
        help="target Windows architecture (default: config or x86_64)",
    )
    plan.add_argument(
        "--extra",
        action="append",
        default=None,
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
        default=None,
        help="target Windows architecture (default: config or x86_64)",
    )
    generate.add_argument(
        "--extra", action="append", default=None, help="select an optional application feature"
    )
    generate.add_argument(
        "--bootstrap",
        choices=("bundled_uv", "online_cmd"),
        default=None,
        help="end-user uv bootstrap strategy (default: config or bundled_uv)",
    )
    generate.add_argument(
        "--system-certs",
        action=argparse.BooleanOptionalAction,
        default=None,
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
    generate.add_argument(
        "--application-wheel",
        type=Path,
        help="supply the validated first-party application wheel required by package mode",
    )
    generate.add_argument("--dry-run", action="store_true")
    validate = commands.add_parser("validate", help="validate a generated deployment kit")
    validate.add_argument("deployment_kit", type=Path)
    validation_mode = validate.add_mutually_exclusive_group()
    validation_mode.add_argument(
        "--static",
        dest="validation_mode",
        action="store_const",
        const="static",
        help="perform non-executing validation (default)",
    )
    validation_mode.add_argument(
        "--runtime",
        dest="validation_mode",
        action="store_const",
        const="runtime",
        help="explicitly install dependencies and execute controlled staged-kit checks",
    )
    validate.set_defaults(validation_mode="static")
    validate.add_argument(
        "--output-dir",
        type=Path,
        help="report directory (default: beside the deployment kit)",
    )
    validate.add_argument(
        "--runtime-root",
        type=Path,
        help="isolated validation state root (runtime mode only)",
    )
    validate.add_argument("--dry-run", action="store_true")
    package = commands.add_parser("package", help="create a validated release-ready ZIP")
    package.add_argument("deployment_kit", type=Path)
    package.add_argument("--output-dir", type=Path)
    package.add_argument("--version", help="application version when absent from the kit manifest")
    package.add_argument("--dry-run", action="store_true")
    all_command = commands.add_parser("all", help="orchestrate assess through package")
    all_command.add_argument("repository")
    all_command.add_argument("--output-dir", type=Path)
    all_command.add_argument("--online", action="store_true")
    all_command.add_argument("--architecture", choices=("x86_64", "arm64"), default=None)
    all_command.add_argument("--extra", action="append", default=None)
    all_command.add_argument(
        "--bootstrap", choices=("bundled_uv", "online_cmd"), default=None
    )
    all_command.add_argument(
        "--system-certs", action=argparse.BooleanOptionalAction, default=None
    )
    all_command.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="DISTRIBUTION=WHEEL",
        help="supply an exact approved exceptional dependency wheel",
    )
    all_command.add_argument(
        "--application-wheel",
        type=Path,
        help="supply the validated first-party application wheel required by package mode",
    )
    all_command.add_argument("--version")
    all_command.add_argument("--runtime-validation", action="store_true")
    all_command.add_argument("--runtime-root", type=Path)
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
    guidance = Counter(item.classification.value for item in assessment.structural_guidance)
    if guidance:
        print("Structural guidance:")
        for classification, count in sorted(guidance.items()):
            print(f"  {count} {classification.replace('_', ' ')}")
    if not assessment.project.entry_points and assessment.entry_point_candidates:
        candidate = assessment.entry_point_candidates[0]
        print(
            "Likely entry point (candidate only): "
            f"{candidate.path} -> {candidate.target or 'unresolved'}"
        )
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 0


def run_plan(
    repository_value: str,
    output_dir: Path | None,
    *,
    online: bool,
    architecture: str | None,
    selected_extras: list[str] | None,
) -> int:
    with materialize_repository(repository_value) as repository:
        settings = resolve_workflow_settings(
            repository.root,
            architecture=architecture,
            bootstrap=None,
            system_certs=None,
            extras=selected_extras,
        )
        assessment = assess_repository(repository)
        chosen_output = output_dir or (
            Path.cwd()
            / "pdbuilder-output"
            / application_id(assessment.project.distribution_name or repository.root.name)
        )
        plan = create_deployment_plan(
            assessment,
            architecture=settings.architecture,
            online=online,
            selected_extras=list(settings.extras),
            repository_root=repository.root,
        )
        json_path, markdown_path = write_deployment_plan_reports(plan, chosen_output.resolve())
    print(
        f"Deployment plan: {plan.risk_gate.outcome.replace('_', ' ')} - "
        f"{plan.deployment_mode} / Python {plan.runtime.python_version} / {plan.runtime.backend} / "
        f"readiness {plan.readiness.state}"
    )
    if plan.entry_point is None and assessment.entry_point_candidates:
        candidate = assessment.entry_point_candidates[0]
        print(
            "Likely entry point (candidate only): "
            f"{candidate.path} -> {candidate.target or 'unresolved'}"
        )
    for blocker in plan.readiness.blockers:
        print(f"Blocker: {blocker}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 1 if plan.readiness.state.startswith("BLOCKED") else 0


def run_generate(
    repository_value: str,
    output_dir: Path | None,
    *,
    online: bool,
    architecture: str | None,
    selected_extras: list[str] | None,
    bootstrap_mode: str | None,
    system_certs: bool | None,
    prepare_lock: bool,
    artifact_values: list[str],
    application_wheel: Path | None,
    dry_run: bool,
) -> int:
    with materialize_repository(repository_value) as repository:
        settings = resolve_workflow_settings(
            repository.root,
            architecture=architecture,
            bootstrap=bootstrap_mode,
            system_certs=system_certs,
            extras=selected_extras,
        )
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
            architecture=settings.architecture,
            online=online,
            selected_extras=list(settings.extras),
            prepare_lock=prepare_lock,
            bootstrap_mode=settings.bootstrap,
            system_certs=settings.system_certs,
            artifact_values=artifact_values,
            application_wheel=application_wheel,
            dry_run=dry_run,
        )
    preview = result.preview
    print(f"Deployment readiness: {preview.readiness_before}")
    print(f"Deployment mode: {preview.deployment_mode}")
    print(
        "Source roots: "
        + (
            ", ".join(preview.source_roots)
            if preview.source_roots
            else "none (installed-project mode)"
        )
    )
    if preview.application_wheel_required:
        print("Application wheel: required (supply --application-wheel PATH)")
    elif preview.application_artifact is not None:
        print(
            "Application wheel: "
            f"{preview.application_artifact.filename} "
            f"(SHA-256 {preview.application_artifact.sha256})"
        )
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


def run_validate(
    deployment_kit: Path,
    output_dir: Path | None,
    runtime_root: Path | None,
    *,
    validation_mode: str,
    dry_run: bool,
) -> int:
    kit_root = deployment_kit.resolve()
    chosen_output = (
        output_dir.resolve()
        if output_dir
        else kit_root.parent / f"{kit_root.name}-validation"
    )
    try:
        chosen_output.relative_to(kit_root)
    except ValueError:
        pass
    else:
        raise ValueError("Validation reports must be written outside the deployment kit.")
    if validation_mode == "runtime":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if runtime_root is None and not local_app_data:
            raise ValueError(
                "LOCALAPPDATA is unavailable; supply an explicit local --runtime-root."
            )
        chosen_runtime = (
            runtime_root.resolve()
            if runtime_root
            else Path(local_app_data)
            / "PDBVal"
            / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        )
        try:
            chosen_runtime.relative_to(kit_root)
        except ValueError:
            pass
        else:
            raise ValueError("The validation runtime root must be outside the deployment kit.")
        report = validate_runtime_kit(kit_root, chosen_runtime, dry_run=dry_run)
    else:
        if runtime_root is not None:
            raise ValueError("--runtime-root is valid only with --runtime.")
        report = validate_static_kit(kit_root, dry_run=dry_run)
    print(f"Validation mode: {report.validation_mode}")
    print(f"Final state: {report.final_state.value}")
    for check in [*report.static_checks, *report.runtime_checks]:
        print(f"  {check.status.value:15} {check.code}: {check.detail}")
    if dry_run:
        print("Dry run only; no validation commands, reports, or runtime files were created.")
    else:
        json_path, markdown_path = write_validation_reports(report, chosen_output)
        print(f"JSON: {json_path}")
        print(f"Markdown: {markdown_path}")
    return 1 if report.final_state.value == "FAILED" else 0


def run_package(
    deployment_kit: Path,
    output_dir: Path | None,
    *,
    version: str | None,
    dry_run: bool,
) -> int:
    result = package_deployment_kit(
        deployment_kit,
        output_directory=output_dir,
        version=version,
        dry_run=dry_run,
    )
    print("KIT VALIDATION")
    print(f"  {result.preview.static_validation_state}")
    print("PACKAGE CREATION")
    print(f"  ZIP: {result.preview.zip_filename}")
    print(f"  Files: {len(result.preview.files_to_package)}")
    if dry_run:
        print("  Files to package:")
        for path in result.preview.files_to_package:
            print(f"    + {path}")
        proposed = Path(result.preview.output_directory)
        print("RELEASE MANIFEST")
        print(f"  Available fields: {', '.join(result.preview.release_manifest_fields)}")
        print("PROPOSED OUTPUT PATHS")
        for path in (
            proposed / result.preview.zip_filename,
            proposed / result.preview.checksum_filename,
            proposed / "release-manifest.json",
            proposed / "release-manifest.md",
            proposed / "SMOKE-TEST.txt",
        ):
            print(f"  {path}")
        print("  Dry run only; no ZIP, reports, extraction, or files were created.")
        return 0
    assert result.manifest is not None
    print("CHECKSUM")
    print(f"  SHA-256: {result.manifest.zip_sha256}")
    print("EXTRACTED PACKAGE VALIDATION")
    print(f"  {result.manifest.extracted_zip_validation_state}")
    print("RELEASE ARTIFACTS")
    for path in (
        result.zip_path,
        result.checksum_path,
        result.manifest_json_path,
        result.manifest_markdown_path,
        result.smoke_test_path,
    ):
        print(f"  {path}")
    print("MANUAL ACCEPTANCE REQUIRED")
    print(f"  Final packaging state: {result.state.value}")
    return 0


def run_all(
    repository_value: str,
    output_dir: Path | None,
    *,
    online: bool,
    architecture: str | None,
    selected_extras: list[str] | None,
    bootstrap_mode: str | None,
    system_certs: bool | None,
    artifact_values: list[str],
    application_wheel: Path | None,
    version: str | None,
    runtime_validation: bool,
    runtime_root: Path | None,
) -> int:
    """Orchestrate existing lifecycle functions without crossing hidden boundaries."""

    if runtime_root is not None and not runtime_validation:
        raise ValueError("--runtime-root requires --runtime-validation.")
    with materialize_repository(repository_value) as repository:
        settings = resolve_workflow_settings(
            repository.root,
            architecture=architecture,
            bootstrap=bootstrap_mode,
            system_certs=system_certs,
            extras=selected_extras,
        )
        assessment = assess_repository(repository)
        app_id = application_id(
            assessment.project.distribution_name or repository.root.name
        )
        workflow_root = (output_dir or Path.cwd() / "pdbuilder-output" / app_id).resolve()
        try:
            workflow_root.relative_to(repository.root.resolve())
        except ValueError:
            pass
        else:
            workflow_root = repository.root.resolve().parent / "pdbuilder-output" / app_id
        reports_root = workflow_root / "reports"
        kit_root = workflow_root / "deployment-kit"
        distribution_root = workflow_root / "distribution"

        print("ASSESS")
        print(f"  {assessment.rating.value}: {assessment.rating_summary}")

        print("PLAN")
        plan = create_deployment_plan(
            assessment,
            architecture=settings.architecture,
            online=online,
            selected_extras=list(settings.extras),
            repository_root=repository.root,
        )
        print(f"  Readiness: {plan.readiness.state}")
        for blocker in plan.readiness.blockers:
            print(f"  Blocker: {blocker}")
        write_assessment_reports(assessment, reports_root)
        write_deployment_plan_reports(plan, reports_root)
        if plan.entry_point is None:
            print(
                "  Stop: declare an authoritative [project.gui-scripts] or "
                "[project.scripts] entry point before generation."
            )
            return 2
        if plan.risk_gate.outcome == "block":
            print("  Stop: planning blockers must be resolved before generation.")
            return 2
        if plan.lockfile.status == "developer_generation_required":
            print(
                "  Stop: uv.lock is missing. Run pdbuilder generate with the explicit "
                "--prepare-lock option, review the repository change, then rerun all."
            )
            return 2
        requirements = plan.lock_graph.artifact_requirements if plan.lock_graph else []
        if requirements and not artifact_values:
            requested = ", ".join(
                f"{item.package}=={item.version}" for item in requirements
            )
            print(
                "  Stop: reviewed developer artifacts are required: "
                f"{requested}. Supply each explicitly with --artifact DISTRIBUTION=WHEEL."
            )
            return 2
        if plan.deployment_mode == "package" and application_wheel is None:
            print(
                "  Stop: package mode requires a validated first-party wheel. "
                "Supply it with --application-wheel PATH."
            )
            return 2

        print("GENERATE")
        generated = generate_deployment_kit(
            repository,
            kit_root,
            architecture=settings.architecture,
            online=online,
            selected_extras=list(settings.extras),
            prepare_lock=False,
            bootstrap_mode=settings.bootstrap,
            system_certs=settings.system_certs,
            artifact_values=artifact_values,
            application_wheel=application_wheel,
            dry_run=False,
        )
        print(f"  Deployment kit: {generated.output_directory}")

        print("STATIC VALIDATE")
        static_report = validate_static_kit(kit_root)
        write_validation_reports(static_report, reports_root / "static-validation")
        print(f"  {static_report.final_state.value}")
        if static_report.final_state.value != "STATIC_VALID":
            return 2

        if runtime_validation:
            print("RUNTIME VALIDATE (EXPLICIT TRUST BOUNDARY)")
            chosen_runtime = runtime_root or workflow_root / "runtime-validation"
            runtime_report = validate_runtime_kit(kit_root, chosen_runtime.resolve())
            write_validation_reports(runtime_report, reports_root / "runtime-validation")
            print(f"  {runtime_report.final_state.value}")
            if runtime_report.final_state.value == "FAILED":
                return 2
        else:
            print("RUNTIME VALIDATE")
            print("  Skipped; use --runtime-validation to explicitly cross the execution boundary.")

        print("PACKAGE")
        packaged = package_deployment_kit(
            kit_root,
            output_directory=distribution_root,
            version=version,
        )
        print(f"  {packaged.state.value}: {packaged.zip_path}")
        return 0


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
                application_wheel=arguments.application_wheel,
                dry_run=arguments.dry_run,
            )
        if arguments.command == "validate":
            return run_validate(
                arguments.deployment_kit,
                arguments.output_dir,
                arguments.runtime_root,
                validation_mode=arguments.validation_mode,
                dry_run=arguments.dry_run,
            )
        if arguments.command == "package":
            return run_package(
                arguments.deployment_kit,
                arguments.output_dir,
                version=arguments.version,
                dry_run=arguments.dry_run,
            )
        if arguments.command == "all":
            return run_all(
                arguments.repository,
                arguments.output_dir,
                online=arguments.online,
                architecture=arguments.architecture,
                selected_extras=arguments.extra,
                bootstrap_mode=arguments.bootstrap,
                system_certs=arguments.system_certs,
                artifact_values=arguments.artifact,
                application_wheel=arguments.application_wheel,
                version=arguments.version,
                runtime_validation=arguments.runtime_validation,
                runtime_root=arguments.runtime_root,
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
