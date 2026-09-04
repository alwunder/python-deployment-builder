from pathlib import Path

from python_deployment_builder.analysis.metadata import inspect_metadata
from python_deployment_builder.models import EntryPointAssessment

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
    assert result.project.entry_points[0].declared_group == "console_scripts"
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
    assert result.project.entry_points[0].declared_group == "gui_scripts"


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
    assert result.project.entry_points[0].declared_group == "console_scripts"
    assert not marker.exists()


def test_entry_point_declared_group_is_independent_from_gui_heuristic(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "example"
version = "1.0"
[project.scripts]
gui-tool = "app:main"
tool = "app.gui:main"
[project.gui-scripts]
native-gui = "app:main"
""",
        encoding="utf-8",
    )

    entries = {item.name: item for item in inspect_metadata(tmp_path).project.entry_points}

    assert (entries["gui-tool"].declared_group, entries["gui-tool"].kind) == (
        "console_scripts",
        "gui",
    )
    assert (entries["tool"].declared_group, entries["tool"].kind) == (
        "console_scripts",
        "gui",
    )
    assert (entries["native-gui"].declared_group, entries["native-gui"].kind) == (
        "gui_scripts",
        "gui",
    )


def test_legacy_and_poetry_entry_point_groups_are_preserved(tmp_path: Path) -> None:
    (tmp_path / "setup.cfg").write_text(
        """[options.entry_points]
console_scripts =
    console = app:main
gui_scripts =
    gui = app:main
""",
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        """from setuptools import setup
setup(entry_points={
    "console_scripts": ["literal-console = app:main"],
    "gui_scripts": ["literal-gui = app:main"],
})
""",
        encoding="utf-8",
    )
    poetry_root = tmp_path / "poetry"
    poetry_root.mkdir()
    (poetry_root / "pyproject.toml").write_text(
        """[tool.poetry]
name = "poetry-example"
version = "1.0"
[tool.poetry.scripts]
poetry-tool = "app:main"
""",
        encoding="utf-8",
    )

    legacy = {item.name: item for item in inspect_metadata(tmp_path).project.entry_points}
    assert legacy["console"].declared_group == "console_scripts"
    assert legacy["gui"].declared_group == "gui_scripts"
    assert legacy["literal-console"].declared_group == "console_scripts"
    assert legacy["literal-gui"].declared_group == "gui_scripts"

    poetry = inspect_metadata(poetry_root).project.entry_points
    assert poetry[0].declared_group == "console_scripts"


def test_older_entry_point_model_forms_default_to_unknown_declared_group() -> None:
    entry = EntryPointAssessment(name="tool", target="app:main", kind="cli")

    assert entry.declared_group == "unknown"


def test_optional_dependency_markers_are_preserved_separately() -> None:
    result = inspect_metadata(FIXTURES / "optional_map_app")

    assert set(result.project.optional_dependency_groups) == {"map", "dev"}
    pywebview = next(item for item in result.dependencies if item.distribution_name == "pywebview")
    assert pywebview.group == "map"
    assert pywebview.environment_marker == 'sys_platform == "win32"'
    assert pywebview.declared_constraint == "<7,>=6"


def test_static_project_version_is_recorded(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "static-version"\nversion = "2.3.4"\n',
        encoding="utf-8",
    )
    assert inspect_metadata(tmp_path).project.version == "2.3.4"


def test_literal_dynamic_version_attr_is_resolved_without_import(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "dynamic-version"\ndynamic = ["version"]\n'
        '[tool.setuptools.dynamic]\nversion = { attr = "version_module.__version__" }\n',
        encoding="utf-8",
    )
    (tmp_path / "version_module.py").write_text(
        f'open({str(marker)!r}, "w").write("executed")\n__version__ = "1.0"\n',
        encoding="utf-8",
    )
    assert inspect_metadata(tmp_path).project.version == "1.0"
    assert not marker.exists()


def test_nonliteral_dynamic_version_attr_remains_unresolved(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "dynamic-version"\ndynamic = ["version"]\n'
        '[tool.setuptools.dynamic]\nversion = { attr = "version_module.__version__" }\n',
        encoding="utf-8",
    )
    (tmp_path / "version_module.py").write_text(
        'VERSION = (1, 0, 0)\n__version__ = ".".join(map(str, VERSION))\n',
        encoding="utf-8",
    )
    assert inspect_metadata(tmp_path).project.version is None
