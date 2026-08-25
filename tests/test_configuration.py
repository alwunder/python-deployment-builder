from pathlib import Path

import pytest

from python_deployment_builder.cli import build_parser, main
from python_deployment_builder.configuration import (
    load_repository_configuration,
    resolve_workflow_settings,
)
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.models import ValidationFinalState
from python_deployment_builder.validation import validate_static_kit


def test_missing_configuration_preserves_defaults(tmp_path: Path) -> None:
    settings = resolve_workflow_settings(
        tmp_path,
        architecture=None,
        bootstrap=None,
        system_certs=None,
        extras=None,
    )
    assert settings.architecture == "x86_64"
    assert settings.bootstrap == "bundled_uv"
    assert not settings.system_certs
    assert settings.extras == ()


def test_configuration_and_cli_override_precedence(tmp_path: Path) -> None:
    (tmp_path / "pdbuilder.toml").write_text(
        '[pdbuilder]\narchitecture = "arm64"\nbootstrap = "online_cmd"\n'
        'system_certs = true\nextras = ["map"]\n',
        encoding="utf-8",
    )
    settings = resolve_workflow_settings(
        tmp_path,
        architecture="x86_64",
        bootstrap="bundled_uv",
        system_certs=False,
        extras=[],
    )
    assert settings.architecture == "x86_64"
    assert settings.bootstrap == "bundled_uv"
    assert not settings.system_certs
    assert settings.extras == ()


def test_configuration_values_override_built_in_defaults(tmp_path: Path) -> None:
    (tmp_path / "pdbuilder.toml").write_text(
        '[pdbuilder]\narchitecture = "arm64"\nbootstrap = "online_cmd"\n'
        'system_certs = true\nextras = ["map", "reports"]\n',
        encoding="utf-8",
    )
    settings = resolve_workflow_settings(
        tmp_path,
        architecture=None,
        bootstrap=None,
        system_certs=None,
        extras=None,
    )
    assert settings.architecture == "arm64"
    assert settings.bootstrap == "online_cmd"
    assert settings.system_certs
    assert settings.extras == ("map", "reports")


@pytest.mark.parametrize(
    "content",
    [
        '[pdbuilder]\nunknown = "value"\n',
        '[pdbuilder]\narchitecture = "sparc"\n',
        '[other]\nvalue = true\n',
        '[pdbuilder]\napproved_wheel = "C:/private/proxy.whl"\n',
        '[pdbuilder]\napi_key = "secret"\n',
        '[pdbuilder]\nextras = ["C:/private/proxy.whl"]\n',
        "[pdbuilder\n",
    ],
)
def test_malformed_or_unknown_configuration_is_rejected(
    tmp_path: Path, content: str
) -> None:
    (tmp_path / "pdbuilder.toml").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid pdbuilder.toml"):
        load_repository_configuration(tmp_path)


def test_all_requires_explicit_runtime_validation_flag() -> None:
    default = build_parser().parse_args(["all", "repository"])
    opted_in = build_parser().parse_args(
        ["all", "repository", "--runtime-validation", "--runtime-root", "runtime"]
    )
    assert not default.runtime_validation
    assert opted_in.runtime_validation


def test_all_rejects_runtime_root_before_work_without_runtime_opt_in(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "prepared_gui"
    workflow = tmp_path / "workflow"
    assert (
        main(
            [
                "all",
                str(fixture),
                "--output-dir",
                str(workflow),
                "--runtime-root",
                str(tmp_path / "runtime"),
            ]
        )
        == 2
    )
    assert not workflow.exists()


def test_all_stops_at_missing_lock_without_preparation(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "target_app"
    assert main(["all", str(fixture), "--output-dir", str(tmp_path / "workflow")]) == 2
    assert not (fixture / "uv.lock").exists()
    assert not (tmp_path / "workflow" / "deployment-kit").exists()


def test_all_stops_at_unsupplied_artifact_requirement(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "optional_map_app"
    result = main(
        [
            "all",
            str(fixture),
            "--extra",
            "map",
            "--output-dir",
            str(tmp_path / "workflow"),
        ]
    )
    assert result == 2
    assert not (tmp_path / "workflow" / "deployment-kit").exists()


def test_all_orchestrates_through_package_without_hidden_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "prepared_gui"
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
    monkeypatch.setattr(
        "python_deployment_builder.cli.validate_runtime_kit",
        lambda *args, **kwargs: pytest.fail("runtime validation was not authorized"),
    )
    workflow = tmp_path / "workflow"
    assert main(["all", str(fixture), "--output-dir", str(workflow)]) == 0
    assert list((workflow / "distribution").glob("*.zip"))


def test_all_runtime_validation_requires_and_honors_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "prepared_gui"
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
    crossed: list[Path] = []

    def fake_runtime(kit: Path, runtime: Path):
        crossed.append(runtime)
        return validate_static_kit(kit)

    monkeypatch.setattr("python_deployment_builder.cli.validate_runtime_kit", fake_runtime)
    workflow = tmp_path / "workflow"
    runtime = tmp_path / "runtime"
    assert (
        main(
            [
                "all",
                str(fixture),
                "--output-dir",
                str(workflow),
                "--runtime-validation",
                "--runtime-root",
                str(runtime),
            ]
        )
        == 0
    )
    assert crossed == [runtime.resolve()]


def test_all_stops_before_packaging_when_static_validation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "prepared_gui"
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

    def failed_static(kit: Path):
        return validate_static_kit(kit).model_copy(
            update={"final_state": ValidationFinalState.FAILED}
        )

    monkeypatch.setattr("python_deployment_builder.cli.validate_static_kit", failed_static)
    monkeypatch.setattr(
        "python_deployment_builder.cli.package_deployment_kit",
        lambda *args, **kwargs: pytest.fail("a statically invalid kit must not be packaged"),
    )
    assert main(["all", str(fixture), "--output-dir", str(tmp_path / "workflow")]) == 2


def test_all_stops_before_packaging_when_runtime_validation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "prepared_gui"
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

    def failed_runtime(kit: Path, runtime: Path):
        del runtime
        return validate_static_kit(kit).model_copy(
            update={"final_state": ValidationFinalState.FAILED}
        )

    monkeypatch.setattr("python_deployment_builder.cli.validate_runtime_kit", failed_runtime)
    monkeypatch.setattr(
        "python_deployment_builder.cli.package_deployment_kit",
        lambda *args, **kwargs: pytest.fail("runtime failure must prevent packaging"),
    )
    assert (
        main(
            [
                "all",
                str(fixture),
                "--output-dir",
                str(tmp_path / "workflow"),
                "--runtime-validation",
            ]
        )
        == 2
    )
