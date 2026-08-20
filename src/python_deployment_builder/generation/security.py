"""Developer-side secret redaction used by preparation and generation errors."""

from __future__ import annotations

import re

PATTERNS = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*)([^\s]+)"), r"\1[REDACTED]"),
    (
        re.compile(r"(?i)((?:api[_-]?key|token|secret)\s*[:=]\s*)([^\s]+)"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)(https?://[^\s:/]+:)([^@\s]+)(@)"), r"\1[REDACTED]\3"),
)


def redact_secrets(value: str) -> str:
    result = value
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)
    return result
