"""Static dependency implementation and Windows-risk hints."""

from __future__ import annotations

from packaging.utils import canonicalize_name

from python_deployment_builder.analysis.imports import distribution_import_names
from python_deployment_builder.models import DependencyAssessment, ImportObservation

NATIVE_DEPENDENCIES = {
    "cffi",
    "cryptography",
    "gdal",
    "numpy",
    "opencv-python",
    "pandas",
    "pillow",
    "psycopg2",
    "pyarrow",
    "pydantic",
    "pydantic-core",
    "pymupdf",
    "pyproj",
    "pyqt5",
    "pyqt6",
    "pyside6",
    "pywin32",
    "scipy",
    "shapely",
}

PURE_PYTHON_DEPENDENCIES = {
    "openai",
    "packaging",
    "pytest",
    "python-dotenv",
    "rich",
    "tksheet",
    "typer",
}

NATIVE_OPTIONAL_DEPENDENCIES = {"pyyaml"}


def enrich_dependencies(
    dependencies: list[DependencyAssessment], observations: list[ImportObservation]
) -> list[DependencyAssessment]:
    """Attach known import names, implementation hints, and observed launch use."""

    observed = {
        observation.distribution_name.lower()
        for observation in observations
        if observation.distribution_name and observation.classification == "declared_third_party"
    }
    import_contexts: dict[str, set[str]] = {}
    optional_flags: dict[str, set[bool]] = {}
    for observation in observations:
        if (
            not observation.distribution_name
            or observation.classification != "declared_third_party"
        ):
            continue
        name = observation.distribution_name.lower()
        import_contexts.setdefault(name, set()).update(observation.contexts)
        optional_flags.setdefault(name, set()).add(observation.optional_import)
    for dependency in dependencies:
        canonical = canonicalize_name(dependency.distribution_name)
        dependency.import_names = list(distribution_import_names(dependency.distribution_name))
        if canonical in NATIVE_DEPENDENCIES:
            dependency.implementation = "native_or_compiled"
            dependency.windows_concern = "medium"
            dependency.source_build_risk = "high"
        elif canonical in NATIVE_OPTIONAL_DEPENDENCIES:
            dependency.implementation = "native_or_compiled"
            dependency.windows_concern = "medium"
            dependency.source_build_risk = "medium"
        elif canonical in PURE_PYTHON_DEPENDENCIES:
            dependency.implementation = "pure_python"
            dependency.windows_concern = "low"
            dependency.source_build_risk = "low"
        else:
            dependency.implementation = "unknown"
            dependency.windows_concern = "unknown"
            dependency.source_build_risk = "unknown"
        lower_name = dependency.distribution_name.lower()
        contexts = import_contexts.get(lower_name, set())
        optional_only = optional_flags.get(lower_name) == {True}
        if (
            dependency.group != "runtime"
            or optional_only
            or (contexts and "module_top_level" not in contexts)
        ):
            dependency.launch_critical = False
        elif lower_name in observed:
            dependency.launch_critical = True
    return dependencies


def apparently_unused_dependencies(
    dependencies: list[DependencyAssessment], observations: list[ImportObservation]
) -> list[str]:
    used = {
        canonicalize_name(observation.distribution_name)
        for observation in observations
        if observation.distribution_name
    }
    return sorted(
        dependency.distribution_name
        for dependency in dependencies
        if dependency.group == "runtime"
        and canonicalize_name(dependency.distribution_name) not in used
    )
