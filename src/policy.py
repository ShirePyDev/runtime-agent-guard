from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Tuple

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
    Keep this as your "policy-as-code" entry point.
    """
    if mode == "strict":
        return PolicyConfig(mode=mode, redact_emails=True, redact_api_keys=True, max_rows=25)
    if mode == "permissive":
        return PolicyConfig(mode=mode, redact_emails=False, redact_api_keys=True, max_rows=100)
    return PolicyConfig(mode="balanced", redact_emails=True, redact_api_keys=True, max_rows=50)


# --------------------------
# Redaction patterns (v2)
# --------------------------
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Key/value style (api_key=..., token: ..., secret=...)
_KV_SECRET_RE = re.compile(
    r"\b(api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*([A-Za-z0-9_\-]{6,})",
    re.IGNORECASE,
)

# JSON style: "api_key": "...."
_JSON_SECRET_RE = re.compile(
    r'("?(api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token)"?\s*:\s*")([^"]{6,})(")',
    re.IGNORECASE,
)

# OpenAI-like keys often start with sk-
_SK_LIKE_RE = re.compile(r"\bsk-[A-Za-z0-9]{10,}\b")

# JWT token pattern: xxx.yyy.zzz (base64url-ish)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# Private key blocks
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
    re.DOTALL,
)


def redact(value: Any, policy: PolicyConfig) -> Any:
    """
    Redact sensitive info from tool outputs BEFORE storing/logging.
    Works for strings, dicts, lists, tuples (common tool outputs).
    Returns the same structure type.
    """
    redacted_value, _summary = redact_with_summary(value, policy)
    return redacted_value


def redact_with_summary(value: Any, policy: PolicyConfig) -> Tuple[Any, Dict[str, int]]:
    """
    Same as redact(), but returns a summary count you can attach to audit logs:
    {"emails": n, "secrets": m}
    """
    summary = {"emails": 0, "secrets": 0}

    def _redact_inner(v: Any) -> Any:
        if v is None:
            return None

        if isinstance(v, str):
            text = v

            if policy.redact_emails:
                matches = list(_EMAIL_RE.finditer(text))
                if matches:
                    summary["emails"] += len(matches)
                    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)

            if policy.redact_api_keys:
                # Private key block
                m = _PRIVATE_KEY_BLOCK_RE.search(text)
                if m:
                    summary["secrets"] += 1
                    text = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY_BLOCK]", text)

                # sk- keys
                matches = list(_SK_LIKE_RE.finditer(text))
                if matches:
                    summary["secrets"] += len(matches)
                    text = _SK_LIKE_RE.sub("[REDACTED_SECRET]", text)

                # JWTs
                matches = list(_JWT_RE.finditer(text))
                if matches:
                    summary["secrets"] += len(matches)
                    text = _JWT_RE.sub("[REDACTED_JWT]", text)

                # key/value style
                matches = list(_KV_SECRET_RE.finditer(text))
                if matches:
                    summary["secrets"] += len(matches)
                    text = _KV_SECRET_RE.sub(r"\1: [REDACTED_SECRET]", text)

                # JSON style
                matches = list(_JSON_SECRET_RE.finditer(text))
                if matches:
                    summary["secrets"] += len(matches)
                    text = _JSON_SECRET_RE.sub(r'\1[REDACTED_SECRET]\4', text)

            return text

        if isinstance(v, dict):
            return {k: _redact_inner(val) for k, val in v.items()}

        if isinstance(v, list):
            return [_redact_inner(x) for x in v]

        if isinstance(v, tuple):
            return tuple(_redact_inner(x) for x in v)

        return v

    out = _redact_inner(value)
    return out, summary
