# src/policy.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Union

PolicyMode = Literal["strict", "balanced", "permissive"]


@dataclass
class PolicyConfig:
    mode: PolicyMode = "balanced"

    # Redaction controls
    redact_emails: bool = True
    redact_api_keys: bool = True

    # SQL output limits
    max_rows: int = 50


def get_policy(mode: PolicyMode = "balanced") -> PolicyConfig:
    """
    Simple policy profiles.
    You can extend this later without touching agent/monitor logic.
    """
    if mode == "strict":
        return PolicyConfig(mode=mode, redact_emails=True, redact_api_keys=True, max_rows=25)
    if mode == "permissive":
        return PolicyConfig(mode=mode, redact_emails=False, redact_api_keys=True, max_rows=100)
    # default: balanced
    return PolicyConfig(mode="balanced", redact_emails=True, redact_api_keys=True, max_rows=50)


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Very simple token/key patterns (baseline; can improve later)
_APIKEY_RE = re.compile(r"\b(api[_-]?key|secret|token)\b\s*[:=]\s*([A-Za-z0-9_\-]{6,})", re.IGNORECASE)


def redact(value: Any, policy: PolicyConfig) -> Any:
    """
    Redact sensitive info from tool outputs BEFORE storing/logging.
    Works for strings, dicts, lists (common tool outputs).
    """
    if value is None:
        return None

    # String redaction
    if isinstance(value, str):
        text = value
        if policy.redact_emails:
            text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        if policy.redact_api_keys:
            text = _APIKEY_RE.sub(r"\1: [REDACTED_SECRET]", text)
        return text

    # Dict redaction
    if isinstance(value, dict):
        return {k: redact(v, policy) for k, v in value.items()}

    # List/Tuple redaction
    if isinstance(value, list):
        return [redact(x, policy) for x in value]
    if isinstance(value, tuple):
        return tuple(redact(x, policy) for x in value)

    # Numbers/booleans/other types unchanged
    return value

