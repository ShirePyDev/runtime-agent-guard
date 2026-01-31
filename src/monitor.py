from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

from src.sql_policy import assess_sql_risk

Decision = Literal["ALLOW", "ASK", "BLOCK"]


@dataclass
class MonitorDecision:
    decision: Decision
    reason: str
    risk_score: float  # 0.0 (safe) → 1.0 (high risk)
    reason_codes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrustIntentMonitor:
    """
    Runtime guard:
    - Tool-specific checks (file, SQL, email, web)
    - Intent drift detection (goal vs action)
    - Repetition escalation (ASK/BLOCK loops)
    - Session risk budget
    - Provenance/taint handling (direct + inferred)
    - Structured audit metadata (args_hash, previews)
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
            "all users",
            "dump",
            "export",
            "send everything",
            "entire database",
            "full list",
            "full user list",
        ]

        self.tool_sensitivity = {
            "search_docs": 0.1,
            "read_file": 0.6,
            "run_sql": 0.7,
            "send_email": 0.9,
            "search_wikipedia": 0.3,
        }

        self.known_tools = set(self.tool_sensitivity.keys())

        # If non-empty => any external domain not in allowlist -> ASK
        self.email_domain_allowlist: Set[str] = set()

        # Session risk budget defaults
        self.default_risk_budget: float = 1.5
        self.risk_budget_ask_threshold: float = 0.2
        self.risk_budget_block_threshold: float = -0.5

        # Taint inference window
        self.taint_history_window: int = 8

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
    # Audit helpers
    # --------------------------
    def _args_hash(self, tool_args: Dict[str, Any]) -> str:
        try:
            s = json.dumps(tool_args or {}, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            s = str(tool_args)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]

    def _attach_audit_defaults(
        self,
        decision: MonitorDecision,
        goal: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> MonitorDecision:
        decision.metadata.setdefault("tool", tool_name)
        decision.metadata.setdefault("args_hash", self._args_hash(tool_args))
        decision.metadata.setdefault("args_preview", self._action_text(tool_name, tool_args))
        decision.metadata.setdefault("goal_preview", self._safe_preview(goal, 200))
        return decision

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
        count = 0
        for h in recent:
            t = h.get("tool") or h.get("tool_name") or h.get("action") or h.get("name")
            d = h.get("decision")
            if t == tool_name and d == decision:
                count += 1
        return count

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
    # Session risk budget
    # --------------------------
    def _apply_risk_budget(
        self,
        base: MonitorDecision,
        session_state: Dict[str, Any],
    ) -> MonitorDecision:
        budget = float(session_state.get("risk_budget", self.default_risk_budget))
        budget -= float(base.risk_score)
        session_state["risk_budget"] = budget
        base.metadata["risk_budget"] = round(budget, 3)

        if budget < self.risk_budget_block_threshold:
            if base.decision != "BLOCK":
                base.decision = "BLOCK"
                base.reason_codes.append("RISK_BUDGET_EXHAUSTED")
                base.risk_score = max(base.risk_score, 0.95)
                base.reason = "Session risk budget exhausted. Blocking further high-risk actions."
            return base

        if budget < self.risk_budget_ask_threshold and base.decision == "ALLOW":
            base.decision = "ASK"
            base.reason_codes.append("RISK_BUDGET_LOW_ESCALATE")
            base.risk_score = max(base.risk_score, 0.6)
            base.reason = "Session risk budget is low. Confirm before continuing."

        return base

    # --------------------------
    # Provenance / taint inference
    # --------------------------
    def _extract_provenance(self, history_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Support multiple shapes to avoid breaking when agent formats history differently.
        """
        md = (
            history_item.get("metadata")
            or history_item.get("monitor_meta")
            or history_item.get("monitor_metadata")
            or {}
        )
        prov = md.get("provenance") or {}
        return prov if isinstance(prov, dict) else {}

    def _infer_taint_from_history(self, history: List[Dict[str, Any]]) -> bool:
        if not history:
            return False
        recent = history[-self.taint_history_window :]
        for h in reversed(recent):
            prov = self._extract_provenance(h)
            if prov.get("tainted") is True:
                return True
        return False

    # --------------------------
    # Main decision function
    # --------------------------
    def evaluate(
        self,
        goal: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        history: Optional[List[Dict[str, Any]]] = None,
        session_state: Optional[Dict[str, Any]] = None,
    ) -> MonitorDecision:
        goal_l = (goal or "").lower()
        tool_name = (tool_name or "").strip()
        tool_args = tool_args or {}
        history = history or []
        session_state = session_state if session_state is not None else {}

        # Unknown tool (monitor-level behavior)
        if tool_name not in self.known_tools:
            d = MonitorDecision(
                decision="ASK",
                reason=f"Unknown tool '{tool_name}'. Confirm before execution.",
                risk_score=0.6,
                reason_codes=["UNKNOWN_TOOL"],
                metadata={"provenance": {"source": "unknown", "tainted": True}},
            )
            d = self._attach_audit_defaults(d, goal, tool_name, tool_args)
            return self._apply_risk_budget(d, session_state)

        if tool_name == "read_file":
            d = self._handle_read_file(tool_args)
        elif tool_name == "search_wikipedia":
            d = self._handle_search_wikipedia(tool_args)
        elif tool_name == "run_sql":
            d = self._handle_run_sql(goal, tool_args)
        elif tool_name == "send_email":
            d = self._handle_send_email(goal_l, tool_args, history)
        else:
            # Low-risk default handler + drift check
            sim = self.intent_similarity(goal, tool_name, tool_args)
            drift = 1.0 - sim
            if drift >= 0.85:
                d = MonitorDecision(
                    decision="ASK",
                    reason=f"Possible intent drift (similarity={sim:.2f}). Confirm.",
                    risk_score=0.5,
                    reason_codes=["INTENT_DRIFT_ASK"],
                    metadata={
                        "similarity": round(sim, 3),
                        "drift": round(drift, 3),
                        "provenance": {"source": "internal", "tainted": False},
                    },
                )
            else:
                d = MonitorDecision(
                    decision="ALLOW",
                    reason="Action allowed.",
                    risk_score=0.2,
                    reason_codes=["DEFAULT_ALLOW"],
                    metadata={"provenance": {"source": "internal", "tainted": False}},
                )

        d = self._escalate_if_repeated(d, tool_name, history)
        d = self._attach_audit_defaults(d, goal, tool_name, tool_args)
        return self._apply_risk_budget(d, session_state)

    # --------------------------
    # Handlers
    # --------------------------
    def _handle_read_file(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        raw = str(tool_args.get("path", "")).strip()
        if not raw:
            return MonitorDecision(
                "ASK",
                "Missing file path.",
                0.5,
                ["MISSING_PATH"],
                {"provenance": {"source": "file", "tainted": False}},
            )

        try:
            resolved = Path(raw).expanduser().resolve()
        except Exception:
            return MonitorDecision(
                "BLOCK",
                "Invalid file path.",
                1.0,
                ["INVALID_PATH"],
                {"provenance": {"source": "file", "tainted": True}},
            )

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
                {"resolved_path": str(resolved), "provenance": {"source": "file", "tainted": True}},
            )

        return MonitorDecision(
            "ALLOW",
            "Reading from allowed docs directory.",
            0.1,
            ["FILE_ALLOWED"],
            {"resolved_path": str(resolved), "provenance": {"source": "file", "tainted": False}},
        )

    def _handle_search_wikipedia(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        q = str(tool_args.get("query", "")).strip()
        if len(q) < 3:
            return MonitorDecision(
                "ASK",
                "Wikipedia query too vague.",
                0.4,
                ["WIKI_QUERY_VAGUE"],
                {"provenance": {"source": "web", "tainted": True}},
            )

        return MonitorDecision(
            "ALLOW",
            "Wikipedia search allowed (tainted output).",
            0.3,
            ["WIKI_ALLOWED_TAINTED"],
            {"provenance": {"source": "web", "tainted": True}},
        )

    def _handle_run_sql(self, goal: str, tool_args: Dict[str, Any]) -> MonitorDecision:
        query = str(tool_args.get("query", "")).strip()
        if not query:
            return MonitorDecision(
                "ASK",
                "Missing SQL query.",
                0.5,
                ["MISSING_SQL_QUERY"],
                {"provenance": {"source": "db", "tainted": False}},
            )

        risk = assess_sql_risk(query, goal)

        if query.lower().startswith("select") and " limit " not in f" {query.lower()} ":
            return MonitorDecision(
                "ASK",
                "SQL SELECT without LIMIT.",
                max(0.6, float(risk.score)),
                ["SQL_MISSING_LIMIT"],
                {"sql_risk_level": risk.level, "provenance": {"source": "db", "tainted": False}},
            )

        if risk.level == "CRITICAL":
            return MonitorDecision(
                "BLOCK",
                risk.reason,
                risk.score,
                ["SQL_CRITICAL"],
                {"sql_risk_level": risk.level, "provenance": {"source": "db", "tainted": False}},
            )

        if risk.level in ("HIGH", "MEDIUM"):
            return MonitorDecision(
                "ASK",
                risk.reason,
                risk.score,
                [f"SQL_{risk.level}"],
                {"sql_risk_level": risk.level, "provenance": {"source": "db", "tainted": False}},
            )

        return MonitorDecision(
            "ALLOW",
            "SQL approved.",
            0.2,
            ["SQL_LOW"],
            {"sql_risk_level": risk.level, "provenance": {"source": "db", "tainted": False}},
        )

    def _handle_send_email(
        self,
        goal_l: str,
        tool_args: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> MonitorDecision:
        to_raw = str(tool_args.get("to", "")).strip()
        subject_raw = str(tool_args.get("subject", "")).strip()
        body_raw = str(tool_args.get("body", "")).strip()

        to_l = to_raw.lower()
        subject_l = subject_raw.lower()
        body_l = body_raw.lower()

        combined = f"{subject_l}\n{body_l}"

        # 1) HARD BLOCKS first (regardless of goal)
        if any(k in combined for k in self.sensitive_keywords):
            return MonitorDecision(
                "BLOCK",
                "Email contains credential-like content.",
                1.0,
                ["EMAIL_CONTAINS_SECRETS"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        if any(k in combined for k in self.exfil_keywords):
            return MonitorDecision(
                "BLOCK",
                "Email appears to exfiltrate data.",
                1.0,
                ["EMAIL_EXFIL_PATTERN"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        # 2) Goal alignment (ASK)
        email_intent_terms = ("email", "send", "mail", "message", "share", "forward", "notify", "report")
        if not any(t in goal_l for t in email_intent_terms):
            return MonitorDecision(
                "ASK",
                "Goal does not indicate sending an email. Confirm before sending.",
                0.6,
                ["EMAIL_NOT_IN_GOAL"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        # 3) Domain allowlist gating (ASK)
        if self.email_domain_allowlist:
            domain = ""
            if "@" in to_l:
                domain = to_l.split("@", 1)[-1].strip()
            if not domain or domain not in self.email_domain_allowlist:
                return MonitorDecision(
                    "ASK",
                    "Recipient domain not allowlisted. Confirm before sending.",
                    0.8,
                    ["EMAIL_DOMAIN_NOT_ALLOWED"],
                    {"domain": domain, "provenance": {"source": "egress", "tainted": True}},
                )

        # 4) Taint (ASK)
        tainted_flag = bool(tool_args.get("tainted"))
        tainted_inferred = self._infer_taint_from_history(history)
        if tainted_flag or tainted_inferred:
            return MonitorDecision(
                "ASK",
                "Email contains untrusted external content (tainted).",
                0.7,
                ["EMAIL_TAINTED_CONTENT"],
                {
                    "tainted_flag": tainted_flag,
                    "tainted_inferred": tainted_inferred,
                    "provenance": {"source": "egress", "tainted": True},
                },
            )

        return MonitorDecision(
            "ALLOW",
            "Email appears safe.",
            0.3,
            ["EMAIL_ALLOWED"],
            {"provenance": {"source": "egress", "tainted": False}},
        )
