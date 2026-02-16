from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

from src.classification import DataClassifier
from src.signals import RiskSignals, classify_sql_entities, parse_sql_entities
from src.sql_policy import extract_tables_and_columns

Decision = Literal["ALLOW", "ASK", "BLOCK"]


@dataclass
class MonitorDecision:
    """
    A single monitor verdict.
    - decision: ALLOW/ASK/BLOCK
    - reason: short human explanation
    - risk_score: 0..1 risk estimate (higher = more risky)
    - reason_codes: machine-readable tags (used in eval)
    - metadata: audit trail and structured context (safe to log)
    """
    decision: Decision
    reason: str
    risk_score: float
    reason_codes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyConfig:
    """
    Policy knobs (what changes per mode/environment).
    Keep *all* policy knobs here to avoid duplicated logic.
    """
    policy_mode: str = "balanced"  # "balanced" | "strict"

    # thresholds
    high_risk_block: float = 0.90
    ask_threshold: float = 0.60

    # email trust boundary
    internal_email_domains: Set[str] = field(default_factory=lambda: {"company.com"})
    allow_internal_email_without_ask: bool = True

    # optional enterprise allowlist
    email_domain_allowlist: Set[str] = field(default_factory=set)

    # taint behavior
    taint_history_window: int = 8
    internal_allows_ignore_taint: bool = False  # keep False for safety-first

    # risk budget
    default_risk_budget: float = 1.0
    risk_budget_ask_threshold: float = 0.2
    risk_budget_block_threshold: float = -0.5


class PolicyEngine:
    """
    Pure policy rules: take signals + context → return a MonitorDecision.
    No printing, no IO, no mutation.
    """

    def __init__(self, cfg: PolicyConfig):
        self.cfg = cfg

    def decide_sql(self, sig: RiskSignals) -> MonitorDecision:
        # Convert classifier hits into stable keys
        classified_keys = [getattr(h, "key", str(h)) for h in (sig.sensitivity_hits or [])]
        classified_hit = bool(classified_keys)

        meta = {
            "signals": {
                "tables": sig.tables,
                "columns": sig.columns,
                "missing_limit": sig.missing_limit,
            },
            "classified_hit": classified_hit,
            "classified_keys": classified_keys,
            "provenance": {"source": "db", "tainted": False},
        }

        # STRICT: any classified SQL is blocked
        if self.cfg.policy_mode == "strict" and classified_hit:
            return MonitorDecision(
                "BLOCK",
                f"Strict mode: blocked classified SQL access: {classified_keys}",
                float(max(sig.base_score, 0.9)),
                ["SQL_CLASSIFIED_BLOCK_STRICT"],
                meta,
            )

        # Hard block if base score is critical
        if sig.base_score >= self.cfg.high_risk_block:
            return MonitorDecision(
                "BLOCK",
                f"SQL access to critical classified data: {classified_keys}",
                float(sig.base_score),
                ["SQL_CRITICAL_CLASSIFIED"],
                meta,
            )

        # Ask if classified or looks bulk (missing LIMIT)
        if sig.base_score >= self.cfg.ask_threshold or sig.missing_limit:
            reason_bits: List[str] = []
            codes: List[str] = []

            if classified_hit:
                reason_bits.append(f"classified={classified_keys}")
                codes.append("SQL_CLASSIFIED_ASK")
            if sig.missing_limit:
                reason_bits.append("missing_limit=True")
                codes.append("SQL_MISSING_LIMIT")

            return MonitorDecision(
                "ASK",
                "SQL requires confirmation (" + ", ".join(reason_bits) + ").",
                float(max(self.cfg.ask_threshold, sig.base_score)),
                codes,
                meta,
            )

        # Otherwise safe SQL
        return MonitorDecision(
            "ALLOW",
            "SQL approved (no classified data detected).",
            0.2,
            ["SQL_LOW"],
            meta,
        )

    def decide_email(
        self,
        *,
        goal_l: str,
        session_state: Dict[str, Any],
        domain: str,
        tainted_flag: bool,
        tainted_inferred: bool,
        uses_taint: bool,
        contains_secret: bool,
        appears_exfil: bool,
        classified_sources: List[Dict[str, Any]],
    ) -> MonitorDecision:
        # 1) hard blocks first
        if contains_secret:
            return MonitorDecision(
                "BLOCK",
                "Email contains credential-like content.",
                1.0,
                ["EMAIL_CONTAINS_SECRETS"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        if appears_exfil:
            return MonitorDecision(
                "BLOCK",
                "Email appears to exfiltrate data.",
                1.0,
                ["EMAIL_EXFIL_PATTERN"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        # 2) multi-step invariant: classified → egress
        if session_state.get("classified_accessed") is True:
            if self.cfg.policy_mode == "strict":
                return MonitorDecision(
                    "BLOCK",
                    "Blocked egress because classified data was accessed earlier in this session (strict mode).",
                    1.0,
                    ["EGRESS_AFTER_CLASSIFIED_BLOCK"],
                    {"classified_sources": classified_sources, "provenance": {"source": "egress", "tainted": True}},
                )
            return MonitorDecision(
                "ASK",
                "Egress requires confirmation because classified data was accessed earlier in this session.",
                0.85,
                ["EGRESS_AFTER_CLASSIFIED_ASK"],
                {"classified_sources": classified_sources, "provenance": {"source": "egress", "tainted": True}},
            )

        # 3) goal alignment (don’t silently email if goal didn’t ask for email)
        email_intent_terms = ("email", "send", "mail", "message", "share", "forward", "notify", "report")
        if not any(t in goal_l for t in email_intent_terms):
            return MonitorDecision(
                "ASK",
                "Goal does not indicate sending an email. Confirm before sending.",
                0.6,
                ["EMAIL_NOT_IN_GOAL"],
                {"provenance": {"source": "egress", "tainted": True}},
            )

        # 4) allowlist mode (if configured)
        if self.cfg.email_domain_allowlist:
            if not domain or domain not in self.cfg.email_domain_allowlist:
                return MonitorDecision(
                    "ASK",
                    "Recipient domain not allowlisted. Confirm before sending.",
                    0.8,
                    ["EMAIL_DOMAIN_NOT_ALLOWED"],
                    {"domain": domain, "provenance": {"source": "egress", "tainted": True}},
                )
            return MonitorDecision(
                "ALLOW",
                "Email allowed: recipient domain allowlisted and content appears safe.",
                0.3,
                ["EMAIL_ALLOWED_ALLOWLIST"],
                {"domain": domain, "provenance": {"source": "egress", "tainted": False}},
            )

        # 5) internal safe auto-allow (your friction reduction)
        internal_ok = bool(domain) and domain in self.cfg.internal_email_domains
        if self.cfg.allow_internal_email_without_ask and internal_ok:
            # Safe internal allow policy:
            # - allow if not tainted at all
            # - OR allow if taint exists but the email does not seem to use tainted content
            if (not tainted_flag and not tainted_inferred) or ((tainted_flag or tainted_inferred) and not uses_taint):
                return MonitorDecision(
                    "ALLOW",
                    "Email allowed: internal recipient and content appears safe.",
                    0.2,
                    ["EMAIL_ALLOWED_INTERNAL_SAFE"],
                    {"domain": domain, "provenance": {"source": "egress", "tainted": False}},
                )


        # 6) taint → ASK (default safety)
        if tainted_flag or tainted_inferred:
            return MonitorDecision(
                "ASK",
                "Email contains untrusted external content (tainted).",
                0.7,
                ["EMAIL_TAINTED_CONTENT"],
                {"tainted_flag": tainted_flag, "tainted_inferred": tainted_inferred, "provenance": {"source": "egress", "tainted": True}},
            )

        # 7) default egress control
        return MonitorDecision(
            "ASK",
            "Email sending requires confirmation (egress control).",
            0.6,
            ["EMAIL_EGRESS_CONFIRM_DEFAULT"],
            {"provenance": {"source": "egress", "tainted": True}},
        )

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

    def __init__(self, allowed_docs_dir: str = "data/docs", policy_mode: str = "balanced") -> None:
        self.allowed_docs_base = Path(allowed_docs_dir).resolve()

        # normalize mode first
        self.policy_mode = (policy_mode or "balanced").lower().strip()
        self.cfg = PolicyConfig(policy_mode=self.policy_mode)
        self.engine = PolicyEngine(self.cfg)


        # detectors
        self.sensitive_keywords = [
            "password", "api key", "apikey", "secret", "token",
            "private key", "ssh", "credential",
        ]
        self.secret_regexes = [
            re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
            re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
            re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----"),
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        ]

        self.classifier = DataClassifier()

        self.exfil_keywords = [
            "all users", "dump", "export", "send everything",
            "entire database", "full list", "full user list",
        ]

        self.tool_sensitivity = {
            "search_docs": 0.1,
            "read_file": 0.6,
            "run_sql": 0.7,
            "send_email": 0.9,
            "search_wikipedia": 0.3,
        }
        self.known_tools = set(self.tool_sensitivity.keys())

        # risk budget settings (from cfg)
        self.default_risk_budget = self.cfg.default_risk_budget
        self.risk_budget_ask_threshold = self.cfg.risk_budget_ask_threshold
        self.risk_budget_block_threshold = self.cfg.risk_budget_block_threshold

        # taint history window (from cfg)
        self.taint_history_window = self.cfg.taint_history_window


    # --------------------------
    # SQL signals
    # --------------------------
    def _build_signals_for_sql(self, goal: str, query: str, tainted_input: bool) -> RiskSignals:
        # sqlglot extractor (returns sets)
        tables_set, columns_set, parsed_ok = extract_tables_and_columns(query)

        # Convert to lists for stable behavior/logging
        tables = sorted(list(tables_set))
        columns = sorted(list(columns_set))

        # Use your signals.py heuristics for missing_limit + bulk
        _, _, missing_limit, bulk = parse_sql_entities(query)

        sig = RiskSignals(tool_name="run_sql", operation="query", goal=goal)
        sig.tables = tables
        sig.columns = columns
        sig.tainted_input = tainted_input
        sig.missing_limit = bool(missing_limit)
        sig.bulk_indicator = bool(bulk)

        # Sensitivity classification
        sig.sensitivity_hits = classify_sql_entities(self.classifier, tables, columns)

        # IMPORTANT: do not manually change base_score/reasons here,
        # finalize() will compute them deterministically
        sig.finalize()
        return sig


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
    # Step 3: High-risk hard block (global, no override)
    # --------------------------
    def _enforce_high_risk_hard_block(self, d: MonitorDecision) -> MonitorDecision:
        """
        Final safety override: if risk_score crosses cfg.high_risk_block, force BLOCK.
        Uses config (single source of truth), no global constants.
        """
        if d.decision == "BLOCK":
            return d

        threshold = float(self.cfg.high_risk_block)
        if float(d.risk_score) >= threshold:
            d.decision = "BLOCK"
            d.reason_codes.append("HIGH_RISK_HARD_BLOCK")
            d.reason = f"{d.reason} (High-risk hard block)"
            d.risk_score = max(float(d.risk_score), threshold)

        return d

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
            dd = h.get("decision")
            if t == tool_name and dd == decision:
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
        # IMPORTANT: do NOT deduct budget for actions that are already BLOCKed
        # (budget should reflect executed/approved actions, not blocked attempts).
        budget = float(session_state.get("risk_budget", self.default_risk_budget))

        # ASK is not executed yet (needs human approval)
        if base.decision == "ALLOW":
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
        recent = history[-self.taint_history_window:]
        for h in reversed(recent):
            prov = self._extract_provenance(h)
            if prov.get("tainted") is True:
                return True
        return False
    
    def _infer_taint_markers(self, history: List[Dict[str, Any]], max_markers: int = 12) -> List[str]:
        """
        Extract lightweight "taint markers" from recent tainted steps.
        These are NOT secrets, just phrases like wikipedia queries.
        We use them to decide whether an outgoing email is actually using tainted content.
        """
        if not history:
            return []

        markers: List[str] = []
        recent = history[-self.taint_history_window:]

        for h in reversed(recent):
            prov = self._extract_provenance(h)
            if prov.get("tainted") is not True:
                continue

            tool = (h.get("tool") or "").strip()
            args = h.get("args") or {}

            # Pull markers from known taint sources
            if tool in {"search_wikipedia", "search_docs"}:
                q = str(args.get("query", "")).strip().lower()
                if q:
                    markers.append(q)
            # If you later add other taint sources, add them here.

            if len(markers) >= max_markers:
                break

        # de-dup while preserving order
        seen = set()
        out: List[str] = []
        for m in markers:
            if m not in seen:
                out.append(m)
                seen.add(m)
        return out


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

        # Unknown tool
        if tool_name not in self.known_tools:
            d = MonitorDecision(
                decision="ASK",
                reason=f"Unknown tool '{tool_name}'. Confirm before execution.",
                risk_score=0.6,
                reason_codes=["UNKNOWN_TOOL"],
                metadata={"provenance": {"source": "unknown", "tainted": True}},
            )
            d = self._attach_audit_defaults(d, goal, tool_name, tool_args)
            d = self._apply_risk_budget(d, session_state)
            return self._enforce_high_risk_hard_block(d)

        if tool_name == "read_file":
            d = self._handle_read_file(tool_args)
        elif tool_name == "search_wikipedia":
            d = self._handle_search_wikipedia(tool_args)
        elif tool_name == "run_sql":
            d = self._handle_run_sql(goal, tool_args, session_state)
        elif tool_name == "send_email":
            # ✅ PASS session_state (required for multi-step rule)
            d = self._handle_send_email(goal_l, tool_args, history, session_state)
        else:
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

        # Order matters:
        # 1) repetition escalation can raise risk/decision
        d = self._escalate_if_repeated(d, tool_name, history)

        # 2) audit defaults
        d = self._attach_audit_defaults(d, goal, tool_name, tool_args)

        # 3) apply budget rules (may escalate ALLOW->ASK, etc.)
        d = self._apply_risk_budget(d, session_state)

        # 4) Step 3 hard-block at high risk (final override)
        d = self._enforce_high_risk_hard_block(d)

        return d

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

    def _handle_run_sql(
        self,
        goal: str,
        tool_args: Dict[str, Any],
        session_state: Dict[str, Any],
    ) -> MonitorDecision:
        query = str(tool_args.get("query", "")).strip()
        if not query:
            return MonitorDecision(
                "ASK",
                "Missing SQL query.",
                0.5,
                ["MISSING_SQL_QUERY"],
                {"classified_hit": False, "classified_keys": [], "provenance": {"source": "db", "tainted": False}},
            )

        sig = self._build_signals_for_sql(goal=goal, query=query, tainted_input=False)
        d = self.engine.decide_sql(sig)

        # ---- session memory for multi-step rule (classified -> egress) ----
        classified_keys = [getattr(h, "key", str(h)) for h in (sig.sensitivity_hits or [])]
        classified_hit = bool(classified_keys)

        if classified_hit:
            session_state["classified_accessed"] = True
            sources = session_state.get("classified_sources")
            if not isinstance(sources, list):
                sources = []
            sources.append(
                {
                    "tool": "run_sql",
                    "tables": sig.tables,
                    "columns": sig.columns,
                    "classified_keys": classified_keys,
                    "missing_limit": sig.missing_limit,
                    "bulk_indicator": sig.bulk_indicator,
                    "base_score": float(sig.base_score),
                }
            )
            session_state["classified_sources"] = sources

        return d


    def _handle_send_email(
        self,
        goal_l: str,
        tool_args: Dict[str, Any],
        history: List[Dict[str, Any]],
        session_state: Dict[str, Any],
        ) -> MonitorDecision:
            to_raw = str(tool_args.get("to", "")).strip()
            subject_raw = str(tool_args.get("subject", "")).strip()
            body_raw = str(tool_args.get("body", "")).strip()

            # 0) Basic validation (ASK)
            if not to_raw or "@" not in to_raw:
                return MonitorDecision(
                    "ASK",
                    "Missing or invalid recipient address. Confirm before sending.",
                    0.5,
                    ["EMAIL_INVALID_RECIPIENT"],
                    {"provenance": {"source": "egress", "tainted": True}},
                )

            to_l = to_raw.lower()
            domain = to_l.split("@", 1)[-1].strip().lower()  # ✅ normalize

            subject_l = subject_raw.lower()
            body_l = body_raw.lower()
            combined = f"{subject_l}\n{body_l}"

            # 1) Hard content detectors
            contains_keyword_secret = any(k in combined for k in self.sensitive_keywords)
            contains_regex_secret = any(r.search(combined) for r in self.secret_regexes)
            contains_secret = contains_keyword_secret or contains_regex_secret

            appears_exfil = any(k in combined for k in self.exfil_keywords)

            # 2) Taint signals
            tainted_flag = bool(tool_args.get("tainted"))
            tainted_inferred = self._infer_taint_from_history(history)

            # Determine whether the email appears to *use* tainted content
            taint_markers = self._infer_taint_markers(history)
            uses_taint = False
            for m in taint_markers:
                if m and (m in subject_l or m in body_l):
                    uses_taint = True
                    break

            classified_sources = session_state.get("classified_sources", []) or []

            # 3) Policy decision (pure engine)
            return self.engine.decide_email(
                goal_l=goal_l,
                session_state=session_state,
                domain=domain,
                tainted_flag=tainted_flag,
                tainted_inferred=tainted_inferred,
                uses_taint=uses_taint,          # ✅ important for Option A
                contains_secret=contains_secret,
                appears_exfil=appears_exfil,
                classified_sources=classified_sources,
            )
