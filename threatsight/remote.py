"""Optional, advisory-only remote model boundary.

This module intentionally has no automatic execution path. Callers must explicitly opt
in, and they remain responsible for review of returned advisory findings.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable


SECRET_PATTERNS = (
    r"sk-[A-Za-z0-9_-]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"(?:ghp|github_pat|glpat|rk_live)[_-][A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}",
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.+?-----END [A-Z ]+ PRIVATE KEY-----",
    r"(?i)(api[_-]?key|password|token)\s*[:=]\s*\S+",
)


def redact_secrets(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = re.sub(pattern, "[REDACTED_SECRET]", text, flags=re.DOTALL)
    return text


def validate_advisory(response: str) -> dict:
    """Validate a minimal remote response schema; reject executable instructions."""
    parsed = json.loads(response)
    if not isinstance(parsed, dict) or set(parsed) - {"summary", "categories", "confidence"}:
        raise ValueError("Remote response does not match the advisory schema")
    if not isinstance(parsed.get("summary"), str):
        raise ValueError("Remote response summary must be text")
    if not isinstance(parsed.get("categories"), list) or not all(isinstance(x, str) for x in parsed["categories"]):
        raise ValueError("Remote response categories must be a list of strings")
    if not isinstance(parsed.get("confidence"), (int, float)) or not 0 <= parsed["confidence"] <= 1:
        raise ValueError("Remote response confidence must be between 0 and 1")
    return parsed


def request_advisory(text: str, transport: Callable[[str, str], str], *, consent: bool = False) -> dict:
    """Send minimized prompt data only after caller records explicit transmission consent.

    Redaction is best-effort and cannot establish that arbitrary input is safe to
    transmit. The caller must apply its approved-data policy before setting consent.
    """
    if not consent:
        raise PermissionError("Explicit consent is required before external prompt transmission")
    api_key = os.environ.get("THREATSIGHT_MODEL_API_KEY")
    if not api_key:
        raise RuntimeError("Set THREATSIGHT_MODEL_API_KEY to opt into remote advisory mode")
    return validate_advisory(transport(redact_secrets(text), api_key))
