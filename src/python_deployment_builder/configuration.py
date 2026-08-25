"""Strict, optional repository defaults for the developer workflow."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, field_validator

from python_deployment_builder.models import StrictModel


class PDBConfiguration(StrictModel):
    architecture: Literal["x86_64", "arm64"] | None = None
    bootstrap: Literal["bundled_uv", "online_cmd"] | None = None
    system_certs: bool | None = None
    extras: list[str] | None = None

    @field_validator("extras")
    @classmethod
    def validate_extras(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) != len(set(value)):
            raise ValueError("extras must not contain duplicates")
        if any(not re.fullmatch(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*", item) for item in value):
            raise ValueError("extras must contain only valid optional-extra names")
        return value


class RepositoryConfiguration(StrictModel):
    pdbuilder: PDBConfiguration = Field(default_factory=PDBConfiguration)


@dataclass(frozen=True)
class WorkflowSettings:
    architecture: Literal["x86_64", "arm64"]
    bootstrap: Literal["bundled_uv", "online_cmd"]
    system_certs: bool
    extras: tuple[str, ...]
    configuration_path: Path | None = None


def load_repository_configuration(
    repository_root: Path,
) -> tuple[RepositoryConfiguration, Path | None]:
    """Load a repository's optional pdbuilder.toml without executing project code."""

    path = repository_root.resolve() / "pdbuilder.toml"
    if not path.is_file():
        return RepositoryConfiguration(), None
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
        configuration = RepositoryConfiguration.model_validate(document)
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ValueError(f"Invalid pdbuilder.toml: {exc}") from exc
    return configuration, path


def resolve_workflow_settings(
    repository_root: Path,
    *,
    architecture: str | None,
    bootstrap: str | None,
    system_certs: bool | None,
    extras: list[str] | None,
) -> WorkflowSettings:
    configuration, path = load_repository_configuration(repository_root)
    section = configuration.pdbuilder
    selected_extras = extras if extras is not None else section.extras or []
    if len(selected_extras) != len(set(selected_extras)):
        raise ValueError("Selected extras must not contain duplicates.")
    if any(not item.strip() for item in selected_extras):
        raise ValueError("Selected extras must be non-empty names.")
    return WorkflowSettings(
        architecture=architecture or section.architecture or "x86_64",
        bootstrap=bootstrap or section.bootstrap or "bundled_uv",
        system_certs=(
            system_certs
            if system_certs is not None
            else section.system_certs
            if section.system_certs is not None
            else False
        ),
        extras=tuple(selected_extras),
        configuration_path=path,
    )


__all__ = [
    "PDBConfiguration",
    "RepositoryConfiguration",
    "WorkflowSettings",
    "load_repository_configuration",
    "resolve_workflow_settings",
]
