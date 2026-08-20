"""Validation of generated deployment kits."""

from python_deployment_builder.validation.runtime import validate_runtime_kit
from python_deployment_builder.validation.static import validate_static_kit

__all__ = ["validate_runtime_kit", "validate_static_kit"]
