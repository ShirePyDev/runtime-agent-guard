from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple
import re


@dataclass(frozen=True)
class RedactionPolicy:
    """
    Post-processing safety layer:
    sanitize tool outputs before logging/history.

    NOTE:
    - 'redact_emails' masks email strings inside text.
    - 'redact_pii_keys' masks values under common PII keys in dict outputs.
      (useful for SQL rows like {"name": "...", "email": "..."}).
    """
    mode: str  # "permissive" | "balanced" | "strict"

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

    # Conservative patterns to reduce false positives.
    patterns: Tuple[Tuple[str, str], ...] = (
        ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
        ("aws_secret_access_key", r"\b[0-9A-Za-z/+=]{40}\b"),
        ("github_pat", r"\bghp_[A-Za-z0-9]{20,}\b"),
        ("generic_token", r"\b(?:token|api[_-]?key|secret)\s*[:=]\s*[\w\-\/\+=]{8,}\b"),
    )

    # Text/email redaction
    redact_emails: bool = False

    # Structured PII redaction (dict keys)
    redact_pii_keys: bool = False
    pii_keys: Tuple[str, ...] = (
        "email",
        "e-mail",
        "mail",
        "name",
        "fullname",
        "full_name",
        "phone",
        "phone_number",
        "mobile",
        "address",
        "ssn",
        "social_security",
    )


def get_policy(mode: str = "balanced") -> RedactionPolicy:
    m = (mode or "balanced").strip().lower()
    if m == "permissive":
        return RedactionPolicy(mode="permissive", redact_emails=False, redact_pii_keys=False)
    if m == "strict":
        return RedactionPolicy(mode="strict", redact_emails=True, redact_pii_keys=True)
    # balanced
    return RedactionPolicy(mode="balanced", redact_emails=False, redact_pii_keys=False)


_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _redact_text_with_stats(text: str, policy: RedactionPolicy) -> Tuple[str, Dict[str, int]]:
    """
    Returns (redacted_text, stats)
    """
    s = text
    stats: Dict[str, int] = {
        "pattern_hits": 0,
        "kv_hits": 0,
        "email_hits": 0,
        "pii_key_hits": 0,
    }

    # 1) Pattern-based redaction
    for (_name, pat) in policy.patterns:
        s, n = re.subn(pat, "[REDACTED]", s)
        stats["pattern_hits"] += n

    # 2) Key-value style redaction (api_key=..., token: ...)
    for k in policy.secret_keys:
        pat = rf"(\b{k}\b\s*[:=]\s*)([^\s,;]+)"
        s, n = re.subn(pat, r"\1[REDACTED]", s, flags=re.IGNORECASE)
        stats["kv_hits"] += n

    # 3) Optional email redaction in text
    if policy.redact_emails:
        s, n = _RE_EMAIL.subn("[REDACTED_EMAIL]", s)
        stats["email_hits"] += n

    return s, stats


def redact(obj: Any, policy: RedactionPolicy) -> Any:
    """
    Backward-compatible API: returns only the redacted object.
    """
    redacted, _stats = redact_with_stats(obj, policy)
    return redacted


def redact_with_stats(obj: Any, policy: RedactionPolicy) -> Tuple[Any, Dict[str, int]]:
    """
    Redact + collect stats for experiments/paper.
    Returns: (redacted_obj, stats)
    """
    totals: Dict[str, int] = {
        "pattern_hits": 0,
        "kv_hits": 0,
        "email_hits": 0,
        "pii_key_hits": 0,
    }

    def add_stats(s: Dict[str, int]) -> None:
        for k in totals:
            totals[k] += int(s.get(k, 0))

    if obj is None:
        return None, totals

    if isinstance(obj, str):
        out, s = _redact_text_with_stats(obj, policy)
        add_stats(s)
        return out, totals

    if isinstance(obj, Mapping):
        redacted: Dict[Any, Any] = {}
        for k, v in obj.items():
            key_str = k.strip().lower() if isinstance(k, str) else None

            # Secrets by key name
            if key_str and key_str in (x.lower() for x in policy.secret_keys):
                redacted[k] = "[REDACTED]"
                totals["kv_hits"] += 1
                continue

            # PII keys (email/name/phone/etc.) for structured outputs
            if key_str and policy.redact_pii_keys and key_str in (x.lower() for x in policy.pii_keys):
                redacted[k] = "[REDACTED_PII]"
                totals["pii_key_hits"] += 1
                continue

            rv, s = redact_with_stats(v, policy)
            redacted[k] = rv
            add_stats(s)

        return redacted, totals

    if isinstance(obj, (list, tuple)):
        items = []
        for x in obj:
            rx, s = redact_with_stats(x, policy)
            items.append(rx)
            add_stats(s)
        return (tuple(items) if isinstance(obj, tuple) else items), totals

    return obj, totals
