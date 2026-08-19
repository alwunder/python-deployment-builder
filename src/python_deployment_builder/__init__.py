"""Developer-side tooling for repeatable, no-admin Python deployments."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("python-deployment-builder")
except PackageNotFoundError:  # pragma: no cover - source tree before installation
    __version__ = "0.1.0"

SCHEMA_VERSION = "1.0"
