from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
import re


# -----------------------------
# Policy definition
# -----------------------------
@dataclass(frozen=True)
class RedactionPolicy:
    """
    RedactionPolicy controls how tool outputs are sanitized before being stored in logs/history.
    This is NOT a detector/monitor; it is a post-processing safety layer.
    """
    mode: str  # "permissive" | "balanced" | "strict"

    # Keyword-based redaction (simple + explainable baseline)
    secret_keys: Tuple[str, ...] = (
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "ssh_key",
    )

    # Regex patterns for common secret-like values
    # Keep these conservative to reduce false positives.
    patterns: Tuple[Tuple[str, str], ...] = (
        ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
        ("aws_secret_access_key", r"\b[0-9A-Za-z/+=]{40}\b"),
        ("github_pat", r"\bghp_[A-Za-z0-9]{20,}\b"),
        ("generic_token", r"\b(?:token|api[_-]?key|secret)\s*[:=]\s*[\w\-\/\+=]{8,}\b"),
    )

    # In strict modes, redact email-like strings too
    redact_emails: bool = False


def get_policy(mode: str = "balanced") -> RedactionPolicy:
    """
    Return a concrete policy configuration by mode.
    The agent calls this once at initialization.
    """
    m = (mode or "balanced").strip().lower()

    if m == "permissive":
        return RedactionPolicy(mode="permissive", redact_emails=False)
    if m == "strict":
        return RedactionPolicy(mode="strict", redact_emails=True)

    # default: balanced
    return RedactionPolicy(mode="balanced", redact_emails=False)


# -----------------------------
# Redaction engine
# -----------------------------
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _redact_text(text: str, policy: RedactionPolicy) -> str:
    s = text

    # 1) Pattern-based redaction
    for (_name, pat) in policy.patterns:
        s = re.sub(pat, "[REDACTED]", s)

    # 2) Key-value style redaction (simple heuristic)
    # e.g., "api_key=XXXXX", "token: XXXXX"
    for k in policy.secret_keys:
        # redact values after key separators
        s = re.sub(
            rf"(\b{k}\b\s*[:=]\s*)([^\s,;]+)",
            r"\1[REDACTED]",
            s,
            flags=re.IGNORECASE,
        )

    # 3) Optional email redaction (strict)
    if policy.redact_emails:
        s = _RE_EMAIL.sub("[REDACTED_EMAIL]", s)

    return s


def redact(obj: Any, policy: RedactionPolicy) -> Any:
    """
    Recursively redact sensitive content from tool results for safe logging.

    Supported inputs:
    - str
    - dict / list / tuple
    - other primitives (returned as-is)
    """
    if obj is None:
        return None

    # Strings
    if isinstance(obj, str):
        return _redact_text(obj, policy)

    # Mappings (dict-like)
    if isinstance(obj, Mapping):
        redacted: Dict[Any, Any] = {}
        for k, v in obj.items():
            # If the key itself indicates secrets, redact the entire value
            if isinstance(k, str) and k.strip().lower() in policy.secret_keys:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact(v, policy)
        return redacted

    # Sequences (list/tuple), but NOT bytes
    if isinstance(obj, (list, tuple)):
        items = [redact(x, policy) for x in obj]
        return tuple(items) if isinstance(obj, tuple) else items

    # For other data types (int/float/bool/etc.), return unchanged
    return obj