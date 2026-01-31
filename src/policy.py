from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple
import re


@dataclass(frozen=True)
class RedactionPolicy:
    """
    Post-processing safety layer:
    sanitize tool outputs before logging/history.
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

    redact_emails: bool = False


def get_policy(mode: str = "balanced") -> RedactionPolicy:
    m = (mode or "balanced").strip().lower()
    if m == "permissive":
        return RedactionPolicy(mode="permissive", redact_emails=False)
    if m == "strict":
        return RedactionPolicy(mode="strict", redact_emails=True)
    return RedactionPolicy(mode="balanced", redact_emails=False)


_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _redact_text_with_stats(text: str, policy: RedactionPolicy) -> Tuple[str, Dict[str, int]]:
    """
    Returns (redacted_text, stats)
    """
    s = text
    stats: Dict[str, int] = {"pattern_hits": 0, "kv_hits": 0, "email_hits": 0}

    # 1) Pattern-based redaction
    for (_name, pat) in policy.patterns:
        before = s
        s = re.sub(pat, "[REDACTED]", s)
        if s != before:
            # Approximate count: number of replacements is hard without re.subn per pattern
            # Use subn for accuracy:
            s, n = re.subn(pat, "[REDACTED]", before)
            stats["pattern_hits"] += n

    # 2) Key-value style redaction (api_key=..., token: ...)
    for k in policy.secret_keys:
        pat = rf"(\b{k}\b\s*[:=]\s*)([^\s,;]+)"
        s, n = re.subn(pat, r"\1[REDACTED]", s, flags=re.IGNORECASE)
        stats["kv_hits"] += n

    # 3) Optional email redaction
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
    totals: Dict[str, int] = {"pattern_hits": 0, "kv_hits": 0, "email_hits": 0}

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
            if isinstance(k, str) and k.strip().lower() in policy.secret_keys:
                redacted[k] = "[REDACTED]"
                totals["kv_hits"] += 1
            else:
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
