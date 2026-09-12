"""Operational write heuristics must not classify descriptive metadata as code."""

import ast
from pathlib import Path, PurePosixPath

import pytest
from test_as_file_relative_imports import as_file_project
from test_generation import _make_application_wheel, _rewrite_application_wheel
from test_review_extra_paths_resources import fake_preparation, repo  # noqa: F401

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import validate_wheel_static_safety
from python_deployment_builder.generation.generator import generate_deployment_kit
from python_deployment_builder.security_policy import text_security_findings
from python_deployment_builder.validation.static import validate_static_kit

DESCRIPTION = (
    "The launcher makes a data-only copy without copying Program Files\nsecurity descriptors."
)
METADATA_HEADER = "Metadata-Version: 2.1\nName: mapped-app\nVersion: 1.2.3\n\n"


def test_descriptive_core_metadata_is_not_an_operational_write(tmp_path):
    wheel = _make_application_wheel(tmp_path)
    _rewrite_application_wheel(
        wheel,
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": METADATA_HEADER + DESCRIPTION,
        },
    )
    validate_wheel_static_safety(wheel)


@pytest.mark.parametrize(
    "path", ["demo-1.dist-info/METADATA", "README.md", "guide.rst", "guide.txt"]
)
def test_descriptive_text_does_not_trigger_write(path):
    assert "program_files_write" not in text_security_findings(
        DESCRIPTION, path=PurePosixPath(path)
    )


@pytest.mark.parametrize(
    "path",
    [
        "main.py",
        "Run.bat",
        "bootstrap.cmd",
        "page.html",
        "script.js",
        "hook.pth",
        "unknown",
        "main.PY",
    ],
)
@pytest.mark.parametrize("operation", ["mkdir", "write_text"])
def test_operational_and_unknown_text_keeps_multiline_write_detection(path, operation):
    text = 'from pathlib import Path\ntarget = Path(r"C:\\Program Files\\Example")\n'
    text += f'target.{operation}("x")\n'
    assert "program_files_write" in text_security_findings(text, path=PurePosixPath(path))


@pytest.mark.parametrize("suffix", ["bat", "cmd"])
def test_actual_batch_copy_into_program_files(suffix):
    text = '@echo off\nset "DEST=C:\\Program Files\\Example"\ncopy state.txt "%DEST%\\state.txt"\n'
    assert "program_files_write" in text_security_findings(
        text, path=PurePosixPath(f"run.{suffix}")
    )


def test_pathless_call_retains_conservative_compatibility():
    assert "program_files_write" in text_security_findings(DESCRIPTION)


@pytest.mark.parametrize(
    "path", ["demo-1.dist-info/METADATA", "README.md", "manual.rst", "guide.txt"]
)
@pytest.mark.parametrize(
    "text,expected",
    [
        ("sk-abcdefghijklmnopqrstuv", "obvious_secret"),
        ("PDBContextConfiguredSecret123", "configured_secret"),
        ("powershell.exe", "forbidden_shell"),
        (r"C:\Users\Developer\project", "developer_path"),
        ("setx PATH example", "permanent_path"),
    ],
)
def test_documentation_keeps_all_other_text_rules(path, text, expected):
    findings = text_security_findings(
        DESCRIPTION + "\n" + text,
        path=PurePosixPath(path),
        configured_secret_values=("PDBContextConfiguredSecret123",),
    )
    assert findings == {expected}


@pytest.mark.parametrize(
    "payload",
    [
        "sk-abcdefghijklmnopqrstuv",
        "PDBContextConfiguredSecret123",
        "powershell.exe",
        r"C:\Users\Developer\project",
    ],
)
def test_wheel_metadata_is_still_security_scanned(tmp_path, payload):
    wheel = _make_application_wheel(tmp_path)
    _rewrite_application_wheel(
        wheel,
        replacements={
            "mapped_app-1.2.3.dist-info/METADATA": METADATA_HEADER + payload,
        },
    )
    with pytest.raises(PreparationError, match="METADATA") as error:
        validate_wheel_static_safety(
            wheel, configured_secret_values=("PDBContextConfiguredSecret123",)
        )
    assert payload not in str(error.value)


@pytest.mark.parametrize("filename", ["README.md", "guide.rst", "guide.txt"])
@pytest.mark.usefixtures("fake_preparation")
def test_staged_documentation_generation_static_parity(tmp_path, filename):
    source = tmp_path / "source"
    as_file_project(source, call=f"as_file(files('app') / {filename!r})")
    (source / "src/app" / filename).write_text(DESCRIPTION)
    kit = tmp_path / "kit"
    generate_deployment_kit(repo(source), kit, bootstrap_mode="online_cmd")
    assert (kit / "src/app" / filename).is_file()
    assert validate_static_kit(kit).final_state.value == "STATIC_VALID"


def test_all_production_scanner_calls_supply_path_context():
    source = Path(__file__).parents[1] / "src/python_deployment_builder"
    callers = []
    for path in source.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "text_security_findings"
            ):
                assert "path" in {keyword.arg for keyword in node.keywords}, str(path)
                callers.append(path.relative_to(source).as_posix())
    assert sorted(callers) == [
        "generation/artifacts.py",
        "generation/structural.py",
        "validation/static.py",
    ]
