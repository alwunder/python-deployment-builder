"""Testable parsing rules mirrored by the pre-Python CMD bootstrap."""

from __future__ import annotations

import re

from python_deployment_builder.generation.acquisition import PreparationError

SHA256_LINE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_certutil_sha256(output: str) -> str:
    """Extract a SHA-256 independent of localized certutil headings and spacing."""

    candidates = {
        compact.lower()
        for line in output.splitlines()
        if SHA256_LINE.fullmatch(compact := "".join(line.split()))
    }
    if len(candidates) != 1:
        raise PreparationError(
            "certutil output must contain exactly one structural 64-digit SHA-256 value."
        )
    return candidates.pop()
