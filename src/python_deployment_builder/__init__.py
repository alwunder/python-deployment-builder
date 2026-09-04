"""Developer-side tooling for repeatable, no-admin Python deployments."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("python-deployment-builder")
except PackageNotFoundError:  # pragma: no cover - source tree before installation
    __version__ = "0.1.0"

SCHEMA_VERSION = "1.0"
# Analysis and planning retain defaults for older serialized forms, but their
# emitted contracts changed when entry-point groups and lock dependency extras became explicit.
ANALYSIS_SCHEMA_VERSION = "1.2"
PLANNING_SCHEMA_VERSION = "1.3"
