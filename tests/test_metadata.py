import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from python_deployment_builder.analysis.metadata import (
    inspect_metadata,
    inspect_setup_call,
    inspect_setuptools_packaging_root,
)
from python_deployment_builder.analysis.resources import resolve_package_data_members
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


def test_setup_call_inspection_distinguishes_absent_literal_and_unresolved_surface_fields(
    tmp_path: Path,
) -> None:
    absent = tmp_path / "absent.py"
    absent.write_text("from setuptools import setup\nsetup(name='demo')\n", encoding="utf-8")
    literal = tmp_path / "literal.py"
    literal.write_text(
        "from setuptools import setup\nsetup(packages=['app'], py_modules=['helper'])\n",
        encoding="utf-8",
    )
    dynamic = tmp_path / "dynamic.py"
    dynamic.write_text(
        "from setuptools import find_packages, setup\n"
        "setup(packages=find_packages(where='src'), package_data=get_data(), **options)\n",
        encoding="utf-8",
    )

    absent_result = inspect_setup_call(absent)
    literal_result = inspect_setup_call(literal)
    dynamic_result = inspect_setup_call(dynamic)

    assert not absent_result.package_selection_present
    assert literal_result.literal_values["packages"] == ["app"]
    assert not literal_result.surface_unresolved
    assert dynamic_result.present_keywords >= {"packages", "package_data"}
    assert dynamic_result.unresolved_keywords >= {"packages", "package_data"}
    assert dynamic_result.has_kwargs_expansion
    assert dynamic_result.surface_unresolved


def test_setup_py_tuple_package_and_module_sequences_are_authoritative(tmp_path: Path) -> None:
    (tmp_path / "lib/app/data").mkdir(parents=True)
    (tmp_path / "lib/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "lib/app/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    (tmp_path / "lib/app/data/default.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "lib/helper.py").write_text("def main(): return 0\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='tuple-demo', version='1.0', packages=('app',), "
        "py_modules=('helper',), package_dir={'': 'lib'}, "
        "package_data={'app': ('data/*.json',)}, install_requires=('requests>=2',))\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.project.packages == ["app"]
    assert result.project.py_modules == ["helper"]
    assert result.project.source_roots == ["lib"]
    assert not result.setuptools_surface_unresolved
    assert [item.distribution_name for item in result.dependencies] == ["requests"]
    package_data_paths = [
        item.source_path for item in resolve_package_data_members(tmp_path, result.project)
    ]
    assert package_data_paths == [
        "lib/app/data/default.json"
    ]


@pytest.mark.parametrize(
    "field, value",
    [
        ("packages", "('app', 1)"),
        ("py_modules", "('helper', 1)"),
    ],
)
def test_setup_py_malformed_literal_selection_remains_unresolved(
    tmp_path: Path, field: str, value: str
) -> None:
    (tmp_path / "setup.py").write_text(
        f"from setuptools import setup\nsetup(name='bad', version='1', {field}={value})\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.setuptools_surface_unresolved
    assert result.project.packages == []
    assert result.project.py_modules == []


def test_dynamic_setup_package_selector_does_not_trigger_automatic_discovery(
    tmp_path: Path,
) -> None:
    (tmp_path / "src/app/tests").mkdir(parents=True)
    for relative in ("src/app/__init__.py", "src/app/main.py", "src/app/tests/__init__.py"):
        (tmp_path / relative).write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='demo-app'\nversion='1.0'\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        "from setuptools import find_packages, setup\n"
        "setup(package_dir={'': 'src'}, packages=find_packages(where='src', "
        "exclude=['app.tests']))\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.project.packages == []
    assert result.setuptools_surface_unresolved
    assert result.setuptools_surface_evidence


def test_setuptools_find_packages_exclude_disposable_wheel_evidence(tmp_path: Path) -> None:
    """Confirm the dynamic selector's real wheel surface without using it in PDB."""

    (tmp_path / "src/app/tests").mkdir(parents=True)
    for relative in (
        "src/app/__init__.py",
        "src/app/main.py",
        "src/app/tests/__init__.py",
        "src/app/tests/test_internal.py",
    ):
        (tmp_path / relative).write_text("", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import find_packages, setup\n"
        "setup(name='demo-app', version='1.0', package_dir={'': 'src'}, "
        "packages=find_packages(where='src', exclude=['app.tests']))\n",
        encoding="utf-8",
    )
    dist = tmp_path / "dist"

    subprocess.run(
        [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(dist)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(dist.glob("demo_app-1.0-*.whl"))
    with zipfile.ZipFile(wheel) as bundle:
        members = set(bundle.namelist())

    assert "app/__init__.py" in members
    assert "app/main.py" in members
    assert "app/tests/__init__.py" not in members


def test_setuptools_package_roots_outside_repository_remain_explicitly_unresolved(
    tmp_path: Path,
) -> None:
    shared = tmp_path.parent / f"{tmp_path.name}-shared"
    (tmp_path / "src/app").mkdir(parents=True)
    (shared / "helper").mkdir(parents=True)
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (shared / "helper/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='external-root-app'\nversion='1.0'\n"
        "[tool.setuptools.packages.find]\n"
        f"where=['src', '../{shared.name}']\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup()\n", encoding="utf-8"
    )

    # Disposable build evidence: setuptools treats both ``where`` entries as
    # build-time package roots, even though PDB must not inspect the sibling.
    subprocess.run(
        [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(tmp_path / "dist")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next((tmp_path / "dist").glob("external_root_app-1.0-*.whl"))
    with zipfile.ZipFile(wheel) as bundle:
        members = set(bundle.namelist())

    result = inspect_metadata(tmp_path)

    assert "app/__init__.py" in members
    assert "helper/__init__.py" in members
    assert result.project.packages == ["app"]
    assert result.project.source_roots == ["src"]
    assert result.setuptools_external_packaging_roots == [f"../{shared.name}"]
    assert result.setuptools_external_packaging_root_evidence


def test_setuptools_packaging_root_validator_distinguishes_safe_missing_and_unsafe(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()

    assert inspect_setuptools_packaging_root(tmp_path, "src").status == "SAFE"
    assert inspect_setuptools_packaging_root(tmp_path, "missing").status == "MISSING_SAFE"
    assert inspect_setuptools_packaging_root(tmp_path, "../shared").status == "UNSAFE"
    assert (
        inspect_setuptools_packaging_root(tmp_path, str(tmp_path.parent / "shared")).status
        == "UNSAFE"
    )


def test_symlinked_setuptools_root_is_not_an_authoritative_repository_root(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    link = tmp_path / "linked-root"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        # Some Windows developer environments disallow symlink creation; the
        # resolver's ordinary outside-root regression remains deterministic.
        return

    assert inspect_setuptools_packaging_root(tmp_path, "linked-root").status == "UNSAFE"


def test_multiple_safe_setuptools_find_roots_remain_authoritative(tmp_path: Path) -> None:
    for relative in ("src/app/__init__.py", "plugins/plugin/__init__.py"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='multi-root'\nversion='1.0'\n"
        "[tool.setuptools.packages.find]\nwhere=['src', 'plugins']\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.project.packages == ["app", "plugin"]
    assert not result.setuptools_external_packaging_roots


def test_external_setuptools_package_dir_is_not_silently_treated_as_in_repository(
    tmp_path: Path,
) -> None:
    external = f"../{tmp_path.name}-shared"
    cases = {
        "pyproject.toml": (
            "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
            "[project]\nname='demo'\nversion='1.0'\n"
            f"[tool.setuptools]\npackage-dir={{''='{external}'}}\n"
        ),
        "setup.cfg": (
            "[metadata]\nname=demo\nversion=1.0\n[options]\n"
            f"package_dir=\n    = {external}\n"
        ),
        "setup.py": (
            "from setuptools import setup\n"
            f"setup(name='demo', version='1.0', package_dir={{'': '{external}'}})\n"
        ),
    }
    for name, content in cases.items():
        root = tmp_path / name.replace(".", "-")
        root.mkdir()
        (root / name).write_text(content, encoding="utf-8")

        result = inspect_metadata(root)

        assert result.setuptools_external_packaging_roots == [external]


def test_setup_cfg_external_find_where_is_not_discarded(tmp_path: Path) -> None:
    external = f"../{tmp_path.name}-shared"
    (tmp_path / "setup.cfg").write_text(
        "[metadata]\nname=demo\nversion=1.0\n[options]\npackages=find:\n"
        f"[options.packages.find]\nwhere=\n    {external}\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)

    assert result.setuptools_external_packaging_roots == [external]


def test_setuptools_finder_unconditional_exclusions_match_disposable_wheel_evidence(
    tmp_path: Path,
) -> None:
    """PackageFinder 79.0.1 excludes ez_setup even without user exclusions."""

    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/ez_setup").mkdir()
    (tmp_path / "src/app/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src/app/main.py").write_text("", encoding="utf-8")
    (tmp_path / "src/ez_setup/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='finder-demo'\nversion='1.0'\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='finder-demo', version='1.0')\n",
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(tmp_path / "dist")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next((tmp_path / "dist").glob("finder_demo-1.0-*.whl"))
    with zipfile.ZipFile(wheel) as bundle:
        members = set(bundle.namelist())

    result = inspect_metadata(tmp_path)
    assert "app/__init__.py" in members
    assert "ez_setup/__init__.py" not in members
    assert result.project.packages == ["app"]


def test_setuptools_finder_unconditional_exclusions_precede_user_include_and_package_data(
    tmp_path: Path,
) -> None:
    (tmp_path / "src/app/data").mkdir(parents=True)
    (tmp_path / "src/ez_setup/data").mkdir(parents=True)
    for relative in ("src/app/__init__.py", "src/ez_setup/__init__.py"):
        (tmp_path / relative).write_text("", encoding="utf-8")
    (tmp_path / "src/app/data/defaults.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src/ez_setup/data/ignored.json").write_text("{}", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='finder-demo'\nversion='1.0'\n"
        "[tool.setuptools.packages.find]\nwhere=['src']\ninclude=['app*', 'ez_setup*']\n"
        "namespaces=false\n"
        "[tool.setuptools.package-data]\n'*'=['data/*.json']\n",
        encoding="utf-8",
    )

    result = inspect_metadata(tmp_path)
    members = resolve_package_data_members(tmp_path, result.project)

    assert result.project.packages == ["app"]
    assert [(item.source_path, item.installed_member_path) for item in members] == [
        ("src/app/data/defaults.json", "app/data/defaults.json")
    ]


def test_setuptools_unconditional_package_exclusions_apply_to_namespace_and_regular_finders(
    tmp_path: Path,
) -> None:
    for namespaces, expected in (("true", ["app"]), ("false", ["app"])):
        project = tmp_path / namespaces
        project.mkdir()
        for relative in ("src/app/__init__.py", "src/ez_setup/__init__.py"):
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("", encoding="utf-8")
        (project / "pyproject.toml").write_text(
            "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
            "[project]\nname='finder-demo'\nversion='1.0'\n"
            "[tool.setuptools.packages.find]\nwhere=['src']\n"
            f"namespaces={namespaces}\n",
            encoding="utf-8",
        )
        assert inspect_metadata(project).project.packages == expected


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
    metadata = inspect_metadata(tmp_path)
    assert metadata.project.version == "1.0"
    assert "version_module.py" in metadata.project.metadata_files
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


@pytest.mark.parametrize(
    ("configuration", "relative"),
    [
        ("[tool.setuptools]\npackage-dir = {'' = 'lib'}\n", "lib/app/__init__.py"),
        ("[tool.setuptools.packages.find]\nwhere = ['python_src']\n", "python_src/app/__init__.py"),
        ("[tool.setuptools]\npackage-dir = {app = 'lib'}\n", "lib/__init__.py"),
    ],
)
def test_literal_dynamic_version_attr_uses_safe_setuptools_package_roots(
    tmp_path: Path, configuration: str, relative: str
) -> None:
    source = tmp_path / relative
    source.parent.mkdir(parents=True)
    source.write_text("__version__ = '1.2.3'\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'dynamic-root-demo'\ndynamic = ['version']\n"
        + configuration
        + "[tool.setuptools.dynamic]\nversion = {attr = 'app.__version__'}\n",
        encoding="utf-8",
    )

    metadata = inspect_metadata(tmp_path)

    assert metadata.project.version == "1.2.3"
    assert relative in metadata.project.metadata_files


def test_literal_dynamic_version_attr_uses_parent_package_dir_mapping(tmp_path: Path) -> None:
    source = tmp_path / "lib/sub/__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text("__version__ = '1.2.3'\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'dynamic-parent-root-demo'\ndynamic = ['version']\n"
        "[tool.setuptools]\npackage-dir = {app = 'lib'}\n"
        "[tool.setuptools.dynamic]\nversion = {attr = 'app.sub.__version__'}\n",
        encoding="utf-8",
    )

    metadata = inspect_metadata(tmp_path)

    assert metadata.project.version == "1.2.3"
    assert "lib/sub/__init__.py" in metadata.project.metadata_files
