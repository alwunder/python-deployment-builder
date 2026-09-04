"""Security rules shared by staged-kit and opaque application-content validation."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

FORBIDDEN_SHELL = ("powershell.exe", "pwsh.exe", "executionpolicy")
WINDOWS_ABSOLUTE = re.compile(r"(?i)[a-z]:\\(?:users|home)\\[^\r\n\"]+")
OBVIOUS_SECRET = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*bearer\s+[a-z0-9._-]{12,}|sk-[a-z0-9_-]{16,})"
)
TEXT_SUFFIXES = frozenset(
    {
        ".bat",
        ".cfg",
        ".cmd",
        ".conf",
        ".config",
        ".csv",
        ".htm",
        ".html",
        ".ini",
        ".json",
        ".md",
        ".py",
        ".rst",
        ".toml",
        ".tsv",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
PROGRAM_FILES_WRITE_TOKENS = ("mkdir", "copy ", "write_text", "open(", "write")
SECRET_FILENAMES = frozenset(
    {".env", "credentials.json", "secrets.json", "token.json", ".pypirc", "pip.ini"}
)
TEXTUAL_WHEEL_METADATA_FILENAMES = frozenset(
    {
        "metadata",
        "wheel",
        "record",
        "entry_points.txt",
        "top_level.txt",
        "installer",
        "requested",
        "direct_url.json",
    }
)


def is_secret_filename(filename: str) -> bool:
    """Return whether a case-insensitive basename is prohibited secret material."""

    lowered = filename.casefold()
    return lowered in SECRET_FILENAMES or (
        lowered.startswith(".env.") and lowered != ".env.example"
    )


def is_textual_wheel_member(path: PurePosixPath) -> bool:
    """Return whether a wheel member has content suitable for text security checks."""

    return path.suffix.lower() in TEXT_SUFFIXES or (
        any(part.casefold().endswith(".dist-info") for part in path.parts)
        and path.name.casefold() in TEXTUAL_WHEEL_METADATA_FILENAMES
    )


def text_security_findings(
    text: str, *, configured_secret_values: Iterable[str] = ()
) -> set[str]:
    """Return the deployment security rules violated by application text."""

    lowered = text.lower()
    findings: set[str] = set()
    if any(item in lowered for item in FORBIDDEN_SHELL):
        findings.add("forbidden_shell")
    if WINDOWS_ABSOLUTE.search(text):
        findings.add("developer_path")
    if "setx" in lowered and "path" in lowered:
        findings.add("permanent_path")
    if "program files" in lowered and any(
        token in lowered for token in PROGRAM_FILES_WRITE_TOKENS
    ):
        findings.add("program_files_write")
    if OBVIOUS_SECRET.search(text):
        findings.add("obvious_secret")
    if any(
        value and len(value) >= 8 and value in text for value in configured_secret_values
    ):
        findings.add("configured_secret")
    return findings


__all__ = [
    "FORBIDDEN_SHELL",
    "TEXT_SUFFIXES",
    "is_secret_filename",
    "is_textual_wheel_member",
    "text_security_findings",
]
