"""Static parsing for PyPA entry-point object references."""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.utils import InvalidName, canonicalize_name


class EntryPointTargetError(ValueError):
    """Raised when an entry-point value is not a bounded object reference."""


@dataclass(frozen=True)
class ParsedEntryPointTarget:
    """Normalized semantics of an entry-point value without importing it."""

    module: str
    attributes: tuple[str, ...]
    extras: tuple[str, ...]

    @property
    def callable_name(self) -> str:
        return ".".join(self.attributes)


_EXTRAS_SUFFIX = re.compile(r"^(?P<object>.*?)\s*\[\s*(?P<extras>[^\[\]]*)\s*\]\s*$")


def _identifier_path(value: str, *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    value = value.strip()
    if not value:
        if allow_empty:
            return ()
        raise EntryPointTargetError(f"Entry-point {label} is empty.")
    components = tuple(value.split("."))
    if any(not component.isidentifier() for component in components):
        raise EntryPointTargetError(
            f"Entry-point {label} is not a dotted Python identifier: {value!r}"
        )
    return components


def _canonical_extras(value: str) -> tuple[str, ...]:
    raw = [item.strip() for item in value.split(",")]
    if not raw or any(not item for item in raw):
        raise EntryPointTargetError("Entry-point extras contain an empty name.")
    try:
        return tuple(sorted({canonicalize_name(item, validate=True) for item in raw}))
    except InvalidName as exc:
        raise EntryPointTargetError("Entry-point extras contain an invalid name.") from exc


def parse_entry_point_target(value: str) -> ParsedEntryPointTarget:
    """Parse ``module[:attributes] [extras]`` using the PyPA bounded grammar."""

    target = value.strip()
    extras: tuple[str, ...] = ()
    if "[" in target or "]" in target:
        matched = _EXTRAS_SUFFIX.fullmatch(target)
        if matched is None:
            raise EntryPointTargetError("Entry-point extras use malformed bracket syntax.")
        target = matched.group("object").strip()
        extras = _canonical_extras(matched.group("extras"))
    if target.count(":") > 1:
        raise EntryPointTargetError("Entry-point object reference contains multiple colons.")
    if ":" in target:
        module_text, attributes_text = target.split(":", 1)
        attributes = _identifier_path(attributes_text, label="attribute path")
    else:
        module_text = target
        attributes = ()
    module = ".".join(_identifier_path(module_text, label="module"))
    return ParsedEntryPointTarget(module=module, attributes=attributes, extras=extras)


__all__ = [
    "EntryPointTargetError",
    "ParsedEntryPointTarget",
    "parse_entry_point_target",
]
