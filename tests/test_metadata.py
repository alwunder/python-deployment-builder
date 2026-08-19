from pathlib import Path

from python_deployment_builder.analysis.metadata import inspect_metadata

FIXTURES = Path(__file__).parent / "fixtures"


def test_pyproject_parsing_and_entry_points() -> None:
    result = inspect_metadata(FIXTURES / "simple_cli")

    assert result.project.distribution_name == "simple-cli"
    assert result.project.layout == "src"
    assert result.python.requires_python == ">=3.11"
    assert result.python.ruff_target_version == "py311"
    assert [(entry.name, entry.target) for entry in result.project.entry_points] == [
        ("simple-cli", "simple_cli.cli:main")
    ]
    assert result.dependencies[0].distribution_name == "requests"


def test_requirements_only_metadata() -> None:
    result = inspect_metadata(FIXTURES / "requirements_only")

    assert result.project.layout == "flat"
    assert {item.distribution_name for item in result.dependencies} == {"PyYAML", "Pillow"}


def test_setup_cfg_is_parsed_statically(tmp_path: Path) -> None:
    (tmp_path / "setup.cfg").write_text(
        """[metadata]
name = configured-app
version = 2.0
[options]
python_requires = >=3.10
install_requires =
    Pillow>=10
[options.packages.find]
where = src
[options.entry_points]
gui_scripts =
    configured-gui = configured_app.gui:main
""",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()

    result = inspect_metadata(tmp_path)

    assert result.project.distribution_name == "configured-app"
    assert result.project.layout == "src"
    assert result.python.requires_python == ">=3.10"
    assert result.dependencies[0].distribution_name == "Pillow"
    assert result.project.entry_points[0].kind == "gui"


def test_setup_py_literals_are_read_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    (tmp_path / "setup.py").write_text(
        f"""from setuptools import setup
open({str(marker)!r}, 'w').write('executed')
setup(name='literal-app', version='1.2', python_requires='>=3.11',
      install_requires=['PyYAML>=6'],
      entry_points={{'console_scripts': ['literal-app = literal_app:main']}})
""",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.project.distribution_name == "literal-app"
    assert result.python.requires_python == ">=3.11"
    assert result.dependencies[0].distribution_name == "PyYAML"
    assert result.project.entry_points[0].target == "literal_app:main"
    assert not marker.exists()
