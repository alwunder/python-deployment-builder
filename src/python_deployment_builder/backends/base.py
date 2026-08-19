"""Interface implemented by deployment runtime backends."""

from __future__ import annotations

from typing import Protocol

from python_deployment_builder.models import RuntimePlan


class RuntimeBackend(Protocol):
    """Build a runtime policy without provisioning anything."""

    name: str

    def build_plan(
        self,
        application_id: str,
        python_version: str,
        architecture: str,
        *,
        deployment_mode: str = "package",
        source_roots: list[str] | None = None,
    ) -> RuntimePlan: ...
