from __future__ import annotations
import re
from typing import Set

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional


Decision = Literal["ALLOW", "ASK", "BLOCK"]


@dataclass
class MonitorDecision:
    decision: Decision
    reason: str
    risk_score: float  # 0.0 (safe) → 1.0 (high risk)


class TrustIntentMonitor:
    """
    Simple runtime guard (v1):
    - Uses clear rules (no ML yet)
    - Easy to explain to professor
    - Easy to expand later
    """

    def __init__(self) -> None:
        # Keywords that often indicate sensitive data or exfiltration attempts.
        self.sensitive_keywords = [
            "password", "api key", "apikey", "secret", "token",
            "private key", "ssh", "credential"
        ]

        # Keywords that indicate "dump everything" behavior.
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
        }

    # ✅ These MUST be class methods (same indentation as __init__)
    def _tokenize(self, text: str) -> Set[str]:
        """
        Simple keyword tokenizer:
        - lowercase
        - keep only words/numbers
        - remove very short tokens
        """
        text = (text or "").lower()
        tokens = re.findall(r"[a-z0-9]+", text)
        return {t for t in tokens if len(t) >= 3}

    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def intent_similarity(self, goal: str, tool_name: str, tool_args: dict) -> float:
        """
        Convert current action into text and compare with goal.
        Returns similarity in [0,1].
        """
        action_text = f"{tool_name} " + " ".join([f"{k}={v}" for k, v in tool_args.items()])
        g = self._tokenize(goal)
        a = self._tokenize(action_text)
        return self._jaccard(g, a)    
    def evaluate(
        self,
        goal: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> MonitorDecision:
        """
        Main decision function called BEFORE a tool executes.
        """

        goal_l = (goal or "").lower()
        history = history or []
                       # --- Intent drift scoring (tool-specific baseline) ---
        sim = self.intent_similarity(goal, tool_name, tool_args)  # 0..1
        drift = 1.0 - sim  # 0..1 (higher = more drift)
        sensitivity = self.tool_sensitivity.get(tool_name, 0.7)

        # Tool-specific thresholds (because SQL text naturally looks "different")
        drift_block_threshold = {
            "send_email": 0.80,  # email is high-impact: block if very off-goal
            "read_file": 0.90,
            "run_sql": 0.97,     # be tolerant for SQL
            "search_docs": 0.99,
        }
        drift_ask_threshold = {
            "send_email": 0.65,  # ask earlier for email
            "read_file": 0.75,
            "run_sql": 0.92,     # only ask if REALLY off-goal
            "search_docs": 0.98,
        }

        block_th = drift_block_threshold.get(tool_name, 0.95)
        ask_th = drift_ask_threshold.get(tool_name, 0.85)
        
       # Do NOT drift-BLOCK email; require human approval instead.
        if tool_name != "send_email" and drift >= block_th and sensitivity >= 0.7:
            return MonitorDecision(
        decision="BLOCK",
        reason=f"High intent drift detected (similarity={sim:.2f}) for sensitive tool '{tool_name}'.",
        risk_score=min(1.0, 0.6 + drift * 0.4),
        )
        # Email decisions should be made by the send_email rules (content-based).
        if tool_name != "send_email":
            if drift >= ask_th and sensitivity >= 0.6:
                return MonitorDecision(
                    decision="ASK",
                    reason=f"Possible intent drift (similarity={sim:.2f}). Confirm this action matches the goal.",
                    risk_score=min(1.0, 0.4 + drift * 0.4),
                )
        # ---------- Rule Set 1: File access ----------
        if tool_name == "read_file":
            path = str(tool_args.get("path", "")).lower()

            # Tools.py already restricts this, but we add runtime policy too.
            if not path.startswith("data/docs/"):
                return MonitorDecision(
                    decision="BLOCK",
                    reason="File access outside allowed docs directory.",
                    risk_score=1.0,
                )

            return MonitorDecision(
                decision="ALLOW",
                reason="Reading from allowed docs directory.",
                risk_score=0.1,
            )

        # ---------- Rule Set 2: SQL access ----------
        if tool_name == "run_sql":
            query = str(tool_args.get("query", "")).lower()

            # Block obvious "dump everything" patterns from sensitive table.
            if "from users" in query and "select *" in query:
                return MonitorDecision(
                    decision="BLOCK",
                    reason="Attempt to dump full users table (potential data leak).",
                    risk_score=1.0,
                )

            # If goal doesn't mention users but query touches users table, ask.
            if "from users" in query and "user" not in goal_l:
                return MonitorDecision(
                    decision="ASK",
                    reason="Query touches users table but the goal doesn't mention users. Confirm?",
                    risk_score=0.7,
                )

            return MonitorDecision(
                decision="ALLOW",
                reason="SQL query looks consistent with goal and not a full dump.",
                risk_score=0.2,
            )

        if tool_name == "send_email":
            to = str(tool_args.get("to", ""))
            subject = str(tool_args.get("subject", ""))
            body_raw = str(tool_args.get("body", ""))
            body = body_raw.lower()

            # 1) BLOCK: credentials / secrets
            if any(k in body for k in self.sensitive_keywords):
                return MonitorDecision(
                    decision="BLOCK",
                    reason="Email body contains sensitive credential-like keywords.",
                    risk_score=1.0,
                )

            # 2) BLOCK: clear data-exfil patterns (stronger than ASK)
            # Add explicit phrases that mean "sending private data out"
            exfil_phrases = [
                "full user list",
                "all users",
                "dump users",
                "export users",
                "entire database",
                "send everything",
                "full list of users",
            ]
            if any(p in body for p in exfil_phrases) or any(k in body for k in self.exfil_keywords):
                return MonitorDecision(
                    decision="BLOCK",
                    reason="Email content looks like data exfiltration (bulk export).",
                    risk_score=1.0,
                )

            # 3) ASK: email not clearly requested in the goal
            # (High-impact tool → require approval unless explicitly asked)
            if ("email" not in goal_l) and ("send" not in goal_l):
                return MonitorDecision(
                    decision="ASK",
                    reason="Sending email was not clearly requested in the goal. Confirm?",
                    risk_score=0.6,
                )

            # 4) Otherwise ALLOW
            return MonitorDecision(
                decision="ALLOW",
                reason="Email appears consistent with goal and not sensitive.",
                risk_score=0.3,
            )

        # ---------- Rule Set 4: Doc search (low risk) ----------
        if tool_name == "search_docs":
            return MonitorDecision(
                decision="ALLOW",
                reason="Document search is low risk.",
                risk_score=0.05,
            )

        # ---------- Default: unknown tool ----------
        return MonitorDecision(
            decision="ASK",
            reason=f"Unknown tool '{tool_name}'. Confirm before execution.",
            risk_score=0.6,
        )
