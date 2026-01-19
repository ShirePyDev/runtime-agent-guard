from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from src.sql_policy import assess_sql_risk

Decision = Literal["ALLOW", "ASK", "BLOCK"]


@dataclass
class MonitorDecision:
    decision: Decision
    reason: str
    risk_score: float  # 0.0 (safe) → 1.0 (high risk)
    reason_codes: List[str] = field(default_factory=list)  # machine-readable labels
    metadata: Dict[str, Any] = field(default_factory=dict)  # extra structured info


class TrustIntentMonitor:
    """
    Runtime guard (v2) - still rule-based, but safer + easier to test:
    - Tool-specific similarity (avoid huge strings)
    - Path traversal defense for read_file
    - Single consolidated send_email logic
    - History-based escalation (repeat attempts)
    - Structured reason_codes + metadata for audit/testing
    """

    # --- compile regex once ---
    _WORD_RE = re.compile(r"[a-z0-9]+")
    _MANY_ROWS_RE = re.compile(r"(\n.*?,.*?){10,}", re.DOTALL)  # crude "CSV dump" detector

    def __init__(self, allowed_docs_dir: str = "data/docs") -> None:
        self.allowed_docs_base = Path(allowed_docs_dir).resolve()

        self.sensitive_keywords = [
            "password", "api key", "apikey", "secret", "token",
            "private key", "ssh", "credential"
        ]

        self.exfil_keywords = [
            "all users", "dump", "export", "send everything",
            "entire database", "full list"
        ]

        # Tool sensitivity levels (higher = more dangerous if misused)
        self.tool_sensitivity = {
            "search_docs": 0.1,
            "read_file": 0.6,
            "run_sql": 0.7,
            "send_email": 0.9,
            "search_wikipedia": 0.3,
        }

        # ✅ MUST come AFTER tool_sensitivity
        self.known_tools = set(self.tool_sensitivity.keys()) | {"search_docs"}

        self.email_domain_allowlist = set()


    # --------------------------
    # Tokenization + similarity
    # --------------------------
    def _tokenize(self, text: str) -> Set[str]:
        text = (text or "").lower()
        tokens = self._WORD_RE.findall(text)
        return {t for t in tokens if len(t) >= 3}

    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def _safe_preview(self, v: Any, limit: int = 200) -> str:
        """
        Convert value to a short string so similarity doesn't get dominated by huge bodies/queries.
        """
        s = str(v) if v is not None else ""
        s = s.replace("\n", " ").strip()
        return s[:limit]

    def _action_text(self, tool_name: str, tool_args: Dict[str, Any]) -> str:
        """
        Tool-specific arg selection (important!).
        Avoid comparing goal against an entire SQL query or entire email body.
        """
        tool_name = tool_name or ""
        args = tool_args or {}

        if tool_name == "read_file":
            return f"read_file path={self._safe_preview(args.get('path', ''), 150)}"

        if tool_name == "run_sql":
            # Only include a short preview; real SQL "drift" is handled by sql_policy anyway
            return f"run_sql query_preview={self._safe_preview(args.get('query', ''), 120)}"

        if tool_name == "send_email":
            return (
                f"send_email to={self._safe_preview(args.get('to', ''), 80)} "
                f"subject={self._safe_preview(args.get('subject', ''), 120)} "
                f"body_preview={self._safe_preview(args.get('body', ''), 160)}"
            )

        if tool_name == "search_wikipedia":
            return f"search_wikipedia query={self._safe_preview(args.get('query', ''), 120)}"

        # default
        pieces = [f"{k}={self._safe_preview(v, 120)}" for k, v in list(args.items())[:6]]
        return f"{tool_name} " + " ".join(pieces)

    def intent_similarity(self, goal: str, tool_name: str, tool_args: Dict[str, Any]) -> float:
        action_text = self._action_text(tool_name, tool_args)
        g = self._tokenize(goal)
        a = self._tokenize(action_text)
        return self._jaccard(g, a)

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
        """
        Count how many times a tool was recently BLOCKed/ASKed/etc.
        History format is up to you; we assume items like:
        {"tool": "send_email", "decision": "BLOCK", "reason_codes": [...], ...}
        """
        recent = history[-window:] if history else []
        c = 0
        for h in recent:
            if h.get("tool") == tool_name and h.get("decision") == decision:
                c += 1
        return c

    def _escalate_if_repeated(
        self,
        base: MonitorDecision,
        tool_name: str,
        history: List[Dict[str, Any]],
    ) -> MonitorDecision:
        """
        If the same tool got blocked recently and the agent tries again, escalate.
        This stops "probing" attacks.
        """
        blocks = self._count_recent_decisions(history, tool_name, "BLOCK")
        asks = self._count_recent_decisions(history, tool_name, "ASK")

        # If repeatedly blocked, keep blocking with higher risk.
        if blocks >= 2 and base.decision != "ALLOW":
            base.reason_codes.append("REPEATED_BLOCKS")
            base.reason = f"{base.reason} (Repeated blocked attempts detected.)"
            base.risk_score = min(1.0, max(base.risk_score, 0.95))
            if base.decision == "ASK":
                base.decision = "BLOCK"  # escalate ASK -> BLOCK
        # If asked many times, force user confirmation (still ASK, but higher risk)
        elif asks >= 3 and base.decision == "ASK":
            base.reason_codes.append("REPEATED_ASKS")
            base.risk_score = min(1.0, max(base.risk_score, 0.75))

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

        # 1) Drift checks for low/medium risk tools only.
        #    We do NOT drift-check send_email or run_sql because they need specialized checks.
                # 1) Drift checks for low/medium risk tools only.
        # Skip send_email/run_sql/read_file (they have special logic).
        sim = self.intent_similarity(goal, tool_name, tool_args)  # 0..1
        drift = 1.0 - sim
        sensitivity = self.tool_sensitivity.get(tool_name, 0.7)

        # Drift checks only for known tools (never for unknown tools).
        if tool_name in getattr(self, "known_tools", set()) and tool_name not in ("send_email", "run_sql", "read_file"):
            block_th = {"search_docs": 0.99}.get(tool_name, 0.95)
            ask_th = {"search_docs": 0.98}.get(tool_name, 0.85)

            if drift >= block_th and sensitivity >= 0.7:
                d = MonitorDecision(
                    decision="BLOCK",
                    reason=f"High intent drift (similarity={sim:.2f}) for sensitive tool '{tool_name}'.",
                    risk_score=min(1.0, 0.6 + drift * 0.4),
                    reason_codes=["INTENT_DRIFT_BLOCK"],
                    metadata={"similarity": round(sim, 3), "drift": round(drift, 3)},
                )
                return self._escalate_if_repeated(d, tool_name, history)

            if drift >= ask_th and sensitivity >= 0.6:
                d = MonitorDecision(
                    decision="ASK",
                    reason=f"Possible intent drift (similarity={sim:.2f}). Confirm it matches the goal.",
                    risk_score=min(1.0, 0.4 + drift * 0.4),
                    reason_codes=["INTENT_DRIFT_ASK"],
                    metadata={"similarity": round(sim, 3), "drift": round(drift, 3)},
                )
                return self._escalate_if_repeated(d, tool_name, history)
        # 2) Tool-specific handlers
        if tool_name == "read_file":
            return self._escalate_if_repeated(self._handle_read_file(tool_args), tool_name, history)

        if tool_name == "search_wikipedia":
            return self._escalate_if_repeated(self._handle_search_wikipedia(tool_args), tool_name, history)

        if tool_name == "run_sql":
            return self._escalate_if_repeated(self._handle_run_sql(goal, tool_args), tool_name, history)

        if tool_name == "send_email":
            return self._escalate_if_repeated(self._handle_send_email(goal_l, tool_args), tool_name, history)

        # 3) Low-risk default
        if tool_name == "search_docs":
            return MonitorDecision(
                decision="ALLOW",
                reason="Document search is low risk.",
                risk_score=0.05,
                reason_codes=["LOW_RISK_TOOL"],
            )

        # 4) Unknown tool → ASK
        return MonitorDecision(
            decision="ASK",
            reason=f"Unknown tool '{tool_name}'. Confirm before execution.",
            risk_score=0.6,
            reason_codes=["UNKNOWN_TOOL"],
            metadata={"tool": tool_name},
        )

    # --------------------------
    # Handlers (clean separation)
    # --------------------------
    def _handle_read_file(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        raw_path = str(tool_args.get("path", "")).strip()
        if not raw_path:
            return MonitorDecision(
                decision="ASK",
                reason="Missing file path. Confirm the intended file.",
                risk_score=0.5,
                reason_codes=["MISSING_PATH"],
            )

        # Path traversal defense:
        # resolve() collapses ../ and returns absolute path
        try:
            resolved = Path(raw_path).expanduser().resolve()
        except Exception:
            return MonitorDecision(
                decision="BLOCK",
                reason="Invalid file path (failed to resolve).",
                risk_score=1.0,
                reason_codes=["INVALID_PATH"],
            )

        # Ensure the resolved path is inside the allowed base directory
        # Python 3.9+: use is_relative_to; for older, do manual prefix check
        try:
            inside = resolved.is_relative_to(self.allowed_docs_base)
        except AttributeError:
            inside = str(resolved).startswith(str(self.allowed_docs_base))

        if not inside:
            return MonitorDecision(
                decision="BLOCK",
                reason="File access outside allowed docs directory.",
                risk_score=1.0,
                reason_codes=["FILE_OUTSIDE_ALLOWED_DIR"],
                metadata={"resolved_path": str(resolved), "allowed_base": str(self.allowed_docs_base)},
            )

        return MonitorDecision(
            decision="ALLOW",
            reason="Reading from allowed docs directory.",
            risk_score=0.1,
            reason_codes=["FILE_ALLOWED"],
            metadata={"resolved_path": str(resolved)},
        )

    def _handle_search_wikipedia(self, tool_args: Dict[str, Any]) -> MonitorDecision:
        query = str(tool_args.get("query", "")).strip()

        # Wikipedia is read-only but untrusted; you can ALLOW, but treat output as tainted later
        if len(query) < 3:
            return MonitorDecision(
                decision="ASK",
                reason="Wikipedia query is too vague. Confirm intent.",
                risk_score=0.4,
                reason_codes=["WIKI_QUERY_VAGUE"],
            )

        return MonitorDecision(
            decision="ALLOW",
            reason="Wikipedia search allowed (read-only). Mark output as tainted for downstream actions.",
            risk_score=0.3,
            reason_codes=["WIKI_ALLOWED_TAINTED"],
        )

    def _handle_run_sql(self, goal: str, tool_args: Dict[str, Any]) -> MonitorDecision:
        query = str(tool_args.get("query", "")).strip()
        if not query:
            return MonitorDecision(
                decision="ASK",
                reason="Missing SQL query. Confirm the intended query.",
                risk_score=0.5,
                reason_codes=["MISSING_SQL_QUERY"],
            )

        risk = assess_sql_risk(query, goal)

        # Suggest enforcing LIMIT at runtime (even if sql_policy is good)
        # We don't mutate SQL here to keep things explainable; we ASK if a LIMIT is missing for SELECT.
        is_select = query.lstrip().lower().startswith("select")
        has_limit = " limit " in f" {query.lower()} "
        if is_select and not has_limit:
            # Don't hard-block immediately; ask for approval because bulk dumping is common
            return MonitorDecision(
                decision="ASK",
                reason="SQL SELECT without LIMIT can dump many rows. Add LIMIT or confirm approval.",
                risk_score=max(0.6, float(getattr(risk, "score", 0.6))),
                reason_codes=["SQL_MISSING_LIMIT"],
                metadata={"sql_risk_level": getattr(risk, "level", "UNKNOWN")},
            )

        if risk.level == "CRITICAL":
            return MonitorDecision(
                decision="BLOCK",
                reason=f"SQL blocked: {risk.reason}",
                risk_score=float(risk.score),
                reason_codes=["SQL_CRITICAL"],
                metadata={"sql_risk_level": risk.level},
            )

        if risk.level in ("HIGH", "MEDIUM"):
            return MonitorDecision(
                decision="ASK",
                reason=f"SQL needs approval: {risk.reason}",
                risk_score=float(risk.score),
                reason_codes=[f"SQL_{risk.level}"],
                metadata={"sql_risk_level": risk.level},
            )

        return MonitorDecision(
            decision="ALLOW",
            reason="SQL approved: low sensitivity by schema-aware check.",
            risk_score=0.2,
            reason_codes=["SQL_LOW"],
            metadata={"sql_risk_level": risk.level},
        )

    def _handle_send_email(self, goal_l: str, tool_args: Dict[str, Any]) -> MonitorDecision:
        to = str(tool_args.get("to", "")).strip()
        subject = str(tool_args.get("subject", "")).strip()
        body_raw = str(tool_args.get("body", ""))
        body_l = body_raw.lower()

        tainted = bool(tool_args.get("tainted", False))
        sources = tool_args.get("taint_sources", []) or []

        # Basic sanity
        if not to:
            return MonitorDecision(
                decision="ASK",
                reason="Missing email recipient 'to'. Confirm who should receive the email.",
                risk_score=0.6,
                reason_codes=["EMAIL_MISSING_TO"],
            )

        # Optional: domain allowlist
        if self.email_domain_allowlist:
            domain = to.split("@")[-1].lower() if "@" in to else ""
            if domain not in self.email_domain_allowlist:
                return MonitorDecision(
                    decision="ASK",
                    reason=f"Recipient domain '{domain}' is not in allowlist. Confirm before sending.",
                    risk_score=0.7,
                    reason_codes=["EMAIL_DOMAIN_NOT_ALLOWED"],
                    metadata={"domain": domain},
                )

        # 1) Untrusted external content → ASK
        if tainted:
            return MonitorDecision(
                decision="ASK",
                reason=f"Email includes untrusted external content (tainted source: {sources}). Confirm before sending.",
                risk_score=0.7,
                reason_codes=["EMAIL_TAINTED_CONTENT"],
                metadata={"taint_sources": sources},
            )

        # 2) BLOCK: credential-like content
        if any(k in body_l for k in self.sensitive_keywords):
            return MonitorDecision(
                decision="BLOCK",
                reason="Email body contains credential/secret-like keywords.",
                risk_score=1.0,
                reason_codes=["EMAIL_CONTAINS_SECRETS"],
            )

        # 3) BLOCK: obvious bulk export / exfil phrases
        exfil_phrases = [
            "full user list",
            "dump users",
            "export users",
            "entire database",
            "send everything",
            "full list of users",
        ]
        if any(p in body_l for p in exfil_phrases) or any(k in body_l for k in self.exfil_keywords):
            return MonitorDecision(
                decision="BLOCK",
                reason="Email content looks like data exfiltration (bulk export).",
                risk_score=1.0,
                reason_codes=["EMAIL_EXFIL_PATTERN"],
            )

        # 4) BLOCK/ASK: looks like table/CSV dump
        if self._MANY_ROWS_RE.search(body_raw):
            return MonitorDecision(
                decision="ASK",
                reason="Email body looks like a bulk data table/CSV. Confirm before sending.",
                risk_score=0.85,
                reason_codes=["EMAIL_BULK_TABLE_LIKE"],
            )

        # 5) ASK: email not clearly requested by goal
        if ("email" not in goal_l) and ("send" not in goal_l):
            return MonitorDecision(
                decision="ASK",
                reason="Sending email was not clearly requested in the goal. Confirm?",
                risk_score=0.6,
                reason_codes=["EMAIL_NOT_IN_GOAL"],
                metadata={"subject": subject[:120]},
            )

        return MonitorDecision(
            decision="ALLOW",
            reason="Email appears consistent with goal and not sensitive.",
            risk_score=0.3,
            reason_codes=["EMAIL_ALLOWED"],
        )
    
