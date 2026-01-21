from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

from src.sql_policy import assess_sql_risk

Decision = Literal["ALLOW", "ASK", "BLOCK"]


# --------------------------
# Decision container
# --------------------------
@dataclass
class MonitorDecision:
    decision: Decision
    reason: str
    risk_score: float  # 0.0 (safe) → 1.0 (high risk)
    reason_codes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# --------------------------
# Runtime Monitor
# --------------------------
class TrustIntentMonitor:
    """
    Runtime guard (v2):
    - Tool-specific intent similarity
    - Path traversal defense
    - SQL schema-aware risk checks
    - Email exfiltration detection
    - History-based escalation
    - Structured audit metadata
    """

    _WORD_RE = re.compile(r"[a-z0-9]+")
    _MANY_ROWS_RE = re.compile(r"(\n.*?,.*?){10,}", re.DOTALL)

    def __init__(self, allowed_docs_dir: str = "data/docs") -> None:
        self.allowed_docs_base = Path(allowed_docs_dir).resolve()

        self.sensitive_keywords = [
            "password", "api key", "apikey", "secret", "token",
            "private key", "ssh", "credential",
        ]

        self.exfil_keywords = [
            "all users", "dump", "export", "send everything",
            "entire database", "full list",
        ]

        self.tool_sensitivity = {
            "search_docs": 0.1,
            "read_file": 0.6,
            "run_sql": 0.7,
            "send_email": 0.9,
            "search_wikipedia": 0.3,
        }

        self.known_tools = set(self.tool_sensitivity.keys())
        self.email_domain_allowlist: Set[str] = set()

    # --------------------------
    # Tokenization + similarity
    # --------------------------
    def _tokenize(self, text: str) -> Set[str]:
        tokens = self._WORD_RE.findall((text or "").lower())
        return {t for t in tokens if len(t) >= 3}

    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        return len(a & b) / len(a | b) if a and b else 0.0

    def _safe_preview(self, v: Any, limit: int = 200) -> str:
        s = str(v) if v is not None else ""
        return s.replace("\n", " ").strip()[:limit]

    def _action_text(self, tool_name: str, tool_args: Dict[str, Any]) -> str:
        args = tool_args or {}

        if tool_name == "read_file":
            return f"path={self._safe_preview(args.get('path'), 150)}"

        if tool_name == "run_sql":
            return f"query={self._safe_preview(args.get('query'), 120)}"

        if tool_name == "send_email":
            return (
                f"to={self._safe_preview(args.get('to'), 80)} "
                f"subject={self._safe_preview(args.get('subject'), 120)} "
                f"body={self._safe_preview(args.get('body'), 160)}"
            )

        if tool_name == "search_wikipedia":
            return f"query={self._safe_preview(args.get('query'), 120)}"

        return " ".join(
            f"{k}={self._safe_preview(v, 120)}"
            for k, v in list(args.items())[:6]
        )

    def intent_similarity(self, goal: str, tool_name: str, tool_args: Dict[str, Any]) -> float:
        return self._jaccard(
            self._tokenize(goal),
            self._tokenize(self._action_text(tool_name, tool_args)),
        )

    # --------------------------
    # History-based escalation
    # --------------------------
    def _count_recent_decisions(
        self,
        history: List[Dict[str, Any]],
        tool_name: str,
        decision: Decision,
        window: int = 6,
    ) -> int:
        recent = history[-window:] if history else []
        return sum(
            1 for h in recent
            if h.get("tool") == tool_name and h.get("decision") == decision
        )

    def _escalate_if_repeated(
        self,
        base: MonitorDecision,
        tool_name: str,
        history: List[Dict[str, Any]],
    ) -> MonitorDecision:
        blocks = self._count_recent_decisions(history, tool_name, "BLOCK")
        asks = self._count_recent_decisions(history, tool_name, "ASK")

        if blocks >= 2 and base.decision != "ALLOW":
            base.reason_codes.append("REPEATED_BLOCKS")
            base.risk_score = max(base.risk_score, 0.95)
            base.decision = "BLOCK"

        elif asks >= 3 and base.decision == "ASK":
            base.reason_codes.append("REPEATED_ASKS")
            base.risk_score = max(base.risk_score, 0.75)

        return base

    # --------------------------
    # Main decision function
    # --------------------------
    def evaluate(
        self,
        goal: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> MonitorDecision:
        goal_l = (goal or "").lower()
        tool_name = (tool_name or "").strip()
        tool_args = tool_args or {}
        history = history or []

        # Unknown tool
        if tool_name not in self.known_tools:
            return MonitorDecision(
                decision="ASK",
                reason=f"Unknown tool '{tool_name}'. Confirm before execution.",
                risk_score=0.6,
                reason_codes=["UNKNOWN_TOOL"],
                metadata={"tool": tool_name},
            )

        # Tool-specific handlers
        if tool_name == "read_file":
            return self._escalate_if_repeated(
                self._handle_read_file(tool_args), tool_name, history
            )

        if tool_name == "search_wikipedia":
            return self._escalate_if_repeated(
                self._handle_search_wikipedia(tool_args), tool_name, history
            )

        if tool_name == "run_sql":
            return self._escalate_if_repeated(
                self._handle_run_sql(goal, tool_args), tool_name, history
            )

        if tool_name == "send_email":
            return self._escalate_if_repeated(
                self._handle_send_email(goal_l, tool_args), tool_name, history
            )

        # Drift check (low-risk tools)
        sim = self.intent_similarity(goal, tool_name, tool_args)
        drift = 1.0 - sim

        if drift >= 0.85:
            return MonitorDecision(
                decision="ASK",
                reason=f"Possible intent drift (similarity={sim:.2f}). Confirm.",
                risk_score=0.5,
                reason_codes=["INTENT_DRIFT_ASK"],
                metadata={"similarity": round(sim, 3), "drift": round(drift, 3)},
            )

        return MonitorDecision(
            decision="ALLOW",
            reason="Action allowed.",
            risk_score=0.2,
            reason_codes=["DEFAULT_ALLOW"],
        )

    # --------------------------
    # Handlers
    # --------------------------
    def _handle_read_file(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        raw = str(tool_args.get("path", "")).strip()
        if not raw:
            return MonitorDecision("ASK", "Missing file path.", 0.5, ["MISSING_PATH"])

        try:
            resolved = Path(raw).expanduser().resolve()
        except Exception:
            return MonitorDecision("BLOCK", "Invalid file path.", 1.0, ["INVALID_PATH"])

        try:
            inside = resolved.is_relative_to(self.allowed_docs_base)
        except AttributeError:
            inside = str(resolved).startswith(str(self.allowed_docs_base))

        if not inside:
            return MonitorDecision(
                "BLOCK",
                "File access outside allowed directory.",
                1.0,
                ["FILE_OUTSIDE_ALLOWED_DIR"],
                {"resolved_path": str(resolved)},
            )

        return MonitorDecision(
            "ALLOW",
            "Reading from allowed docs directory.",
            0.1,
            ["FILE_ALLOWED"],
            {"resolved_path": str(resolved)},
        )

    def _handle_search_wikipedia(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        q = str(tool_args.get("query", "")).strip()
        if len(q) < 3:
            return MonitorDecision("ASK", "Wikipedia query too vague.", 0.4, ["WIKI_QUERY_VAGUE"])

        return MonitorDecision(
            "ALLOW",
            "Wikipedia search allowed (tainted output).",
            0.3,
            ["WIKI_ALLOWED_TAINTED"],
        )

    def _handle_run_sql(self, goal: str, tool_args: Dict[str, Any]) -> MonitorDecision:
        query = str(tool_args.get("query", "")).strip()
        if not query:
            return MonitorDecision("ASK", "Missing SQL query.", 0.5, ["MISSING_SQL_QUERY"])

        risk = assess_sql_risk(query, goal)

        if query.lower().startswith("select") and " limit " not in f" {query.lower()} ":
            return MonitorDecision(
                "ASK",
                "SQL SELECT without LIMIT.",
                max(0.6, float(risk.score)),
                ["SQL_MISSING_LIMIT"],
                {"sql_risk_level": risk.level},
            )

        if risk.level == "CRITICAL":
            return MonitorDecision("BLOCK", risk.reason, risk.score, ["SQL_CRITICAL"])

        if risk.level in ("HIGH", "MEDIUM"):
            return MonitorDecision("ASK", risk.reason, risk.score, [f"SQL_{risk.level}"])

        return MonitorDecision(
            "ALLOW",
            "SQL approved.",
            0.2,
            ["SQL_LOW"],
            {"sql_risk_level": risk.level},
        )

    def _handle_send_email(self, goal_l: str, tool_args: Dict[str, Any]) -> MonitorDecision:
        body = str(tool_args.get("body", "")).lower()

        if tool_args.get("tainted"):
            return MonitorDecision(
                "ASK",
                "Email contains untrusted external content.",
                0.7,
                ["EMAIL_TAINTED_CONTENT"],
            )

        if any(k in body for k in self.sensitive_keywords):
            return MonitorDecision(
                "BLOCK",
                "Email contains credential-like content.",
                1.0,
                ["EMAIL_CONTAINS_SECRETS"],
            )

        if any(k in body for k in self.exfil_keywords):
            return MonitorDecision(
                "BLOCK",
                "Email appears to exfiltrate data.",
                1.0,
                ["EMAIL_EXFIL_PATTERN"],
            )

        return MonitorDecision(
            "ALLOW",
            "Email appears safe.",
            0.3,
            ["EMAIL_ALLOWED"],
        )
