from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.logger import save_run
from src.monitor import TrustIntentMonitor, MonitorDecision
from src.policy import get_policy, redact
from src.tools import TOOLS, ToolResult


# -------------------------
# Hard-stop Exceptions (enterprise-grade)
# -------------------------
class RuntimeGuardStop(Exception):
    """Raised when the runtime guard terminates execution (BLOCK or human denial)."""


class HumanDenied(RuntimeGuardStop):
    """Raised when an ASK decision is denied by a human (or non-interactive mode)."""


class PolicyBlocked(RuntimeGuardStop):
    """Raised when a decision is BLOCK."""


@dataclass
class StepRecord:
    step: int
    goal: str
    tool: str
    args: Dict[str, Any]

    decision: str
    reason: str
    risk_score: float
    reason_codes: List[str] = field(default_factory=list)

    # Tool execution results
    tool_ok: Optional[bool] = None
    tool_result: Optional[Any] = None
    tool_error: Optional[str] = None
    tool_meta: Dict[str, Any] = field(default_factory=dict)

    # Monitor metadata (e.g., resolved path, sql risk level, etc.)
    monitor_meta: Dict[str, Any] = field(default_factory=dict)

    # Approval tracking (ASK flow)
    approved: Optional[bool] = None
    approved_by: Optional[str] = None


class SimpleRuntimeAgent:
    """
    Minimal agent runtime loop:
    - Evaluate each proposed tool call with runtime monitor BEFORE execution
    - Enforce decisions: ALLOW / ASK / BLOCK
    - Supports human approval for ASK (interactive)
    - Logs a full, audit-friendly history (paper-ready)

    Strong safety semantics:
    - BLOCK => immediate termination (no tool execution)
    - ASK + deny => immediate termination
    - Once terminated, future run() calls will not execute anything
    """

    def __init__(self, goal: str, policy_mode: str = "balanced"):
        self.goal = goal
        self.monitor = TrustIntentMonitor(policy_mode=policy_mode)
        self.policy = get_policy(policy_mode)
        self.history: List[StepRecord] = []
        self.session_state: Dict[str, Any] = {}

    @staticmethod
    def _sanitize_tool_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove monitor-only fields so tools don't accidentally depend on them.
        """
        exec_args = dict(tool_args or {})
        exec_args.pop("tainted", None)
        exec_args.pop("taint_sources", None)
        return exec_args

    def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> ToolResult:
        tool_fn = TOOLS.get(tool_name)
        if tool_fn is None:
            return ToolResult(ok=False, error=f"Unknown tool: {tool_name}")

        try:
            return tool_fn(**(tool_args or {}))
        except TypeError as e:
            return ToolResult(ok=False, error=f"Bad tool arguments for '{tool_name}': {e}")
        except Exception as e:
            return ToolResult(ok=False, error=f"Tool '{tool_name}' failed: {e}")

    def _effective_redaction_policy(self, tool_name: str, reason_codes: List[str]) -> Any:
        """
        Decide how aggressively to redact tool outputs before storing in history.
        This is defense-in-depth: even after a human approves, we avoid leaking.

        Expected policy structure (flexible):
          - policy["redaction"][tool_name]            -> normal redaction config
          - policy["redaction_strict"][tool_name]     -> strict redaction config
          - policy["redaction_default"]               -> default config

        If your src.policy uses a different shape, this function still degrades safely.
        """
        pol = self.policy if isinstance(self.policy, dict) else {}

        # Base policy
        base = (
            pol.get("redaction", {}).get(tool_name)
            if isinstance(pol.get("redaction"), dict)
            else None
        )
        if base is None:
            base = pol.get("redaction_default", None)

        # Escalate to strict when classified-related codes are present
        classified_related = any(
            (c or "").startswith("SQL_CLASSIFIED")
            or (c or "").startswith("SQL_CRITICAL_CLASSIFIED")
            or (c or "").startswith("EGRESS_AFTER_CLASSIFIED")
            for c in (reason_codes or [])
        )

        if classified_related:
            strict = (
                pol.get("redaction_strict", {}).get(tool_name)
                if isinstance(pol.get("redaction_strict"), dict)
                else None
            )
            return strict if strict is not None else base

        return base

    def run(
        self,
        proposed_actions: List[Dict[str, Any]],
        interactive: bool = True,
        auto_confirm: bool = False,
    ) -> List[StepRecord]:
        """
        proposed_actions: list of {"tool": "...", "args": {...}}

        auto_confirm:
          - False = ASK requires explicit approval (safe default)
          - True  = treat ASK like ALLOW (debug/testing only)

        IMPORTANT:
          - If the session is terminated (BLOCK or denial), run() will not execute further actions.
        """
        try:
            # If a previous run was terminated, don't continue.
            if self.session_state.get("terminated") is True:
                return self.history

            start_step = len(self.history) + 1

            for i, action in enumerate(proposed_actions, start=start_step):
                # If termination happened mid-loop, stop immediately.
                if self.session_state.get("terminated") is True:
                    break

                tool_name = str(action.get("tool", "")).strip()
                tool_args = action.get("args", {}) or {}

                # -------------------------
                # Early validation (clean + audit-friendly)
                # -------------------------
                if not tool_name:
                    self.history.append(
                        StepRecord(
                            step=i,
                            goal=self.goal,
                            tool=tool_name,
                            args=tool_args,
                            decision="BLOCK",
                            reason="Missing tool name.",
                            risk_score=1.0,
                            reason_codes=["MISSING_TOOL_NAME"],
                        )
                    )
                    self.session_state["terminated"] = True
                    raise PolicyBlocked("Missing tool name (BLOCK).")

                if tool_name not in TOOLS:
                    self.history.append(
                        StepRecord(
                            step=i,
                            goal=self.goal,
                            tool=tool_name,
                            args=tool_args,
                            decision="BLOCK",
                            reason=f"Unknown tool: {tool_name}",
                            risk_score=1.0,
                            reason_codes=["UNKNOWN_TOOL"],
                        )
                    )
                    self.session_state["terminated"] = True
                    raise PolicyBlocked(f"Unknown tool '{tool_name}' (BLOCK).")

                # Convert history into simple dicts for the monitor (no StepRecord dependency)
                history_for_monitor: List[Dict[str, Any]] = []
                for r in self.history:
                    merged_meta: Dict[str, Any] = {}

                    if isinstance(getattr(r, "monitor_meta", None), dict):
                        merged_meta.update(r.monitor_meta)

                    # Ensure provenance is a dict; if missing/bad, fall back to tool_meta provenance
                    prov = merged_meta.get("provenance")
                    if not isinstance(prov, dict):
                        tool_meta = getattr(r, "tool_meta", None)
                        if isinstance(tool_meta, dict) and isinstance(tool_meta.get("provenance"), dict):
                            merged_meta["provenance"] = tool_meta["provenance"]

                    history_for_monitor.append(
                        {
                            "tool": r.tool,
                            "args": r.args,
                            "decision": r.decision,
                            "risk_score": r.risk_score,
                            "reason_codes": getattr(r, "reason_codes", None),
                            "monitor_meta": merged_meta,
                        }
                    )

                md: MonitorDecision = self.monitor.evaluate(
                    goal=self.goal,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    history=history_for_monitor,
                    session_state=self.session_state,
                )

                record = StepRecord(
                    step=i,
                    goal=self.goal,
                    tool=tool_name,
                    args=tool_args,
                    decision=md.decision,
                    reason=md.reason,
                    risk_score=md.risk_score,
                    reason_codes=getattr(md, "reason_codes", []) or [],
                    monitor_meta=getattr(md, "metadata", None) or {},
                )

                # -------------------------
                # Enforce decision: BLOCK (hard stop)
                # -------------------------
                if md.decision == "BLOCK":
                    self.history.append(record)
                    self.session_state["terminated"] = True
                    raise PolicyBlocked(f"Blocked by policy at step {i}: {md.reason}")

                # -------------------------
                # Enforce decision: ASK (manual approval)
                # -------------------------
                if md.decision == "ASK" and not auto_confirm:
                    self.history.append(record)

                    if not interactive:
                        # Non-interactive => terminate safely
                        record.approved = False
                        record.approved_by = "non_interactive"
                        self.session_state["terminated"] = True
                        raise HumanDenied(f"ASK decision in non-interactive mode at step {i}.")

                    print("\n=== APPROVAL REQUIRED ===")
                    print(f"Goal: {self.goal}")
                    print(f"Proposed tool: {tool_name}")
                    print(f"Arguments: {tool_args}")
                    print(f"Risk score: {md.risk_score}")
                    print(f"Reason: {md.reason}")

                    user_choice = input("Approve this action? (y/n): ").strip().lower()

                    if user_choice not in ("y", "yes"):
                        record.approved = False
                        record.approved_by = "human"
                        self.session_state["terminated"] = True
                        raise HumanDenied(f"Human denied approval at step {i}.")

                    # Approved: execute tool ONCE and update the last record
                    exec_args = self._sanitize_tool_args(tool_args)
                    tool_result = self._execute_tool(tool_name, exec_args)

                    last = self.history[-1]
                    last.approved = True
                    last.approved_by = "human"
                    last.tool_ok = tool_result.ok
                    eff = self._effective_redaction_policy(tool_name, last.reason_codes)
                    last.tool_result = redact(tool_result.result, eff)
                    last.tool_error = tool_result.error
                    last.tool_meta = tool_result.meta or {}

                    # --- Multi-step state (correct): mark classified access only AFTER successful SQL execution ---
                    if tool_name == "run_sql" and tool_result.ok:
                        classified_hit = bool((last.monitor_meta or {}).get("classified_hit"))
                        if classified_hit:
                            self.session_state["classified_accessed"] = True
                            self.session_state.setdefault("classified_sources", [])
                            self.session_state["classified_sources"].append(
                                {
                                    "step": i,
                                    "tool": tool_name,
                                    "tables": ((last.monitor_meta or {}).get("signals") or {}).get("tables", []),
                                    "classified_keys": (last.monitor_meta or {}).get("classified_keys", []),
                                    "args_hash": (last.monitor_meta or {}).get("args_hash"),
                                }
                            )

                    # For audit readability, mark as ALLOW after approval
                    last.decision = "ALLOW"
                    last.reason = f"{last.reason} (Approved by human)"

                    continue

                # -------------------------
                # ALLOW (or ASK with auto_confirm)
                # -------------------------
                if md.decision == "ASK" and auto_confirm:
                    record.approved = True
                    record.approved_by = "auto_confirm"
                    record.decision = "ALLOW"
                    record.reason = f"{record.reason} (Auto-confirmed)"

                # Execute tool
                exec_args = self._sanitize_tool_args(tool_args)
                tool_result = self._execute_tool(tool_name, exec_args)

                record.tool_ok = tool_result.ok
                eff = self._effective_redaction_policy(tool_name, record.reason_codes)
                record.tool_result = redact(tool_result.result, eff)
                record.tool_error = tool_result.error
                record.tool_meta = tool_result.meta or {}

                # --- Multi-step state (correct): mark classified access only AFTER successful SQL execution ---
                if tool_name == "run_sql" and tool_result.ok:
                    classified_hit = bool((record.monitor_meta or {}).get("classified_hit"))
                    if classified_hit:
                        self.session_state["classified_accessed"] = True
                        self.session_state.setdefault("classified_sources", [])
                        self.session_state["classified_sources"].append(
                            {
                                "step": i,
                                "tool": tool_name,
                                "tables": ((record.monitor_meta or {}).get("signals") or {}).get("tables", []),
                                "classified_keys": (record.monitor_meta or {}).get("classified_keys", []),
                                "args_hash": (record.monitor_meta or {}).get("args_hash"),
                            }
                        )

                self.history.append(record)

            return self.history

        finally:
            # Always save full runtime trace (even on crashes or early termination)
            save_run(self.history, self.goal)
