"""Serialized absence, not an empty value, selects legacy secret compatibility."""

import json

import pytest
from test_generation import (
    _make_application_wheel,
    _make_wheel,
    _refresh_manifest_wheel_hash,
    _repository,
    _rewrite_application_wheel,
    _update_indexed_hashes,
    _write_mapped_project,
)
from test_validation import _kit, _refresh_manifest_index, _status

from python_deployment_builder.analysis.repository import MaterializedRepository
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.generation.manifest import effective_configuration_secret_names
from python_deployment_builder.generation.preparation import LockPreparationResult
from python_deployment_builder.models import ValidationCheckStatus
from python_deployment_builder.validation.runtime import _manifest, _runtime_environment
from python_deployment_builder.validation.static import _load_manifest, validate_static_kit


def configure_manifest(kit, presence, secrets=None):
    path = kit / "deployment/manifest.json"
    payload = json.loads(path.read_text())
    payload["configuration_presence_names"] = presence
    if secrets is None:
        payload.pop("configuration_secret_names", None)
    else:
        payload["configuration_secret_names"] = secrets
    path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest_index(kit)


@pytest.mark.parametrize("relative", ["src/prepared_gui/main.py", "deployment/runtime/launch.py"])
def test_legacy_configured_value_is_scanned_in_indexed_text(tmp_path, monkeypatch, relative):
    kit = _kit(monkeypatch, tmp_path)
    # Select a real indexed application source without depending on fixture module spelling.
    if relative.startswith("src/"):
        relative = next(
            p.relative_to(kit).as_posix()
            for p in kit.rglob("*.py")
            if "deployment" not in p.relative_to(kit).parts
        )
    configure_manifest(kit, ["DB_PASSWORD"])
    manifest = _load_manifest(kit)
    assert manifest.configuration_secret_names == []
    assert "configuration_secret_names" not in manifest.model_fields_set
    secret = "PDBLegacyConfiguredSecret123"
    monkeypatch.setenv("DB_PASSWORD", secret)
    path = kit / relative
    path.write_text(path.read_text() + f"\n# ordinary fixture {secret}\n")
    _update_indexed_hashes(kit, relative)
    report = validate_static_kit(kit)
    assert _status(report, "NO_SECRET_CONTENT") == ValidationCheckStatus.FAIL
    assert secret not in report.model_dump_json()


@pytest.mark.parametrize("value", [None, "", "482731"])
def test_legacy_unset_empty_and_short_values(tmp_path, monkeypatch, caplog, value):
    kit = _kit(monkeypatch, tmp_path)
    configure_manifest(kit, ["DEMO_PIN"])
    monkeypatch.delenv("DEMO_PIN", raising=False)
    if value is not None:
        monkeypatch.setenv("DEMO_PIN", value)
    report = validate_static_kit(kit)
    if value:
        assert _status(report, "CONFIGURED_SECRET_SCANABILITY") == ValidationCheckStatus.FAIL
        assert "SHORT_CONFIGURED_SECRET_UNSCANNABLE" in report.model_dump_json()
        assert value not in report.model_dump_json() + caplog.text
        assert value not in (kit / "deployment/manifest.json").read_text()
    else:
        assert report.final_state.value == "STATIC_VALID"


@pytest.mark.parametrize("secrets", [[], ["DB_PASSWORD"]])
@pytest.mark.parametrize("embed_secret", [False, True])
def test_current_secret_set_does_not_fall_back(tmp_path, monkeypatch, secrets, embed_secret):
    kit = _kit(monkeypatch, tmp_path)
    configure_manifest(kit, ["DISPLAY_THEME", "DB_PASSWORD"], secrets)
    manifest = _load_manifest(kit)
    assert "configuration_secret_names" in manifest.model_fields_set
    assert effective_configuration_secret_names(manifest) == secrets
    secret = "PDBLegacyConfiguredSecret123"
    monkeypatch.setenv("DISPLAY_THEME", "dark")
    monkeypatch.setenv("DB_PASSWORD", secret)
    relative = "deployment/runtime/launch.py"
    path = kit / relative
    path.write_text(path.read_text() + "\n# dark\n" + (f"# {secret}\n" if embed_secret else ""))
    _update_indexed_hashes(kit, relative)
    report = validate_static_kit(kit)
    fails = bool(secrets) and embed_secret
    assert (_status(report, "NO_SECRET_CONTENT") == ValidationCheckStatus.FAIL) == fails
    if not fails:
        assert report.final_state.value == "STATIC_VALID"
    assert secret not in report.model_dump_json()


def test_current_generation_serializes_explicit_empty_secret_set(tmp_path, monkeypatch):
    kit = _kit(monkeypatch, tmp_path)
    payload = json.loads((kit / "deployment/manifest.json").read_text())
    assert payload["configuration_secret_names"] == []
    assert "configuration_secret_names" in _load_manifest(kit).model_fields_set


@pytest.mark.parametrize("omit", [False, True])
@pytest.mark.parametrize("mode", ["source", "package"])
def test_application_artifact_default_has_no_absence_ambiguity(tmp_path, monkeypatch, omit, mode):
    kit = _kit(monkeypatch, tmp_path)
    path = kit / "deployment/manifest.json"
    payload = json.loads(path.read_text())
    payload["deployment_mode"] = mode
    if omit:
        payload.pop("application_artifact", None)
    else:
        payload["application_artifact"] = None
    path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest_index(kit)
    report = validate_static_kit(kit)
    assert (_status(report, "APPLICATION_ARTIFACT_HASH") == ValidationCheckStatus.FAIL) == (
        mode == "package"
    )
    if mode == "source":
        assert report.final_state.value == "STATIC_VALID"


@pytest.mark.parametrize("secrets", [None, []])
def test_runtime_isolation_still_uses_presence_names(tmp_path, monkeypatch, secrets):
    kit = _kit(monkeypatch, tmp_path)
    configure_manifest(kit, ["DISPLAY_THEME", "DB_PASSWORD", "LOCALAPPDATA"], secrets)
    runtime_manifest = _manifest(kit)
    assert effective_configuration_secret_names(runtime_manifest) == (
        ["DISPLAY_THEME", "DB_PASSWORD", "LOCALAPPDATA"] if secrets is None else []
    )
    monkeypatch.setenv("DISPLAY_THEME", "dark")
    monkeypatch.setenv("DB_PASSWORD", "PDBLegacyConfiguredSecret123")
    harness_root = tmp_path / "harness"
    environment = _runtime_environment(_load_manifest(kit), harness_root)
    assert "DISPLAY_THEME" not in environment
    assert "DB_PASSWORD" not in environment
    assert environment["LOCALAPPDATA"] == str(harness_root)


@pytest.mark.parametrize("kind", ["approved", "application"])
def test_legacy_secret_set_reaches_wheel_member_scanners(tmp_path, monkeypatch, caplog, kind):
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
    kit = tmp_path / "kit"
    if kind == "approved":
        wheel = _make_wheel(tmp_path)
        generate_deployment_kit(
            _repository("optional_map_app"),
            kit,
            selected_extras=["map"],
            artifact_values=[f"proxy-tools={wheel}"],
            bootstrap_mode="online_cmd",
        )
        relative = f"deployment/wheels/{wheel.name}"
        member = "proxy_tools/settings.txt"
    else:
        source = tmp_path / "source"
        source.mkdir()
        _write_mapped_project(source)
        wheel = _make_application_wheel(tmp_path)
        generate_deployment_kit(
            MaterializedRepository(root=source, source=str(source), source_kind="local"),
            kit,
            application_wheel=wheel,
            bootstrap_mode="online_cmd",
        )
        relative = f"deployment/application/{wheel.name}"
        member = "installed_app/view.html"
    assert validate_static_kit(kit).final_state.value == "STATIC_VALID"
    secret = "PDBLegacyConfiguredSecret123"
    _rewrite_application_wheel(kit / relative, additions={member: f"ordinary text {secret}"})
    _refresh_manifest_wheel_hash(kit, relative, approved=kind == "approved")
    configure_manifest(kit, ["DB_PASSWORD"])
    monkeypatch.setenv("DB_PASSWORD", secret)
    report = validate_static_kit(kit)
    assert _status(report, "WHEEL_SECURITY") == ValidationCheckStatus.FAIL
    assert secret not in report.model_dump_json() + caplog.text
    assert secret not in (kit / "deployment/manifest.json").read_text()
