from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.logger import save_run
from src.monitor import TrustIntentMonitor, MonitorDecision
from src.policy import get_policy, redact
from src.tools import TOOLS, ToolResult


@dataclass
class StepRecord:
    step: int
    goal: str
    tool: str
    args: Dict[str, Any]
    decision: str
    reason: str
    risk_score: float
    tool_ok: Optional[bool] = None
    tool_result: Optional[Any] = None
    tool_error: Optional[str] = None
    tool_meta: Dict[str, Any] = field(default_factory=dict)
    monitor_meta: Dict[str, Any] = field(default_factory=dict)




class SimpleRuntimeAgent:
    """
    Minimal agent runtime loop:
    - Evaluates each proposed tool call with the runtime monitor BEFORE execution
    - Enforces decisions: ALLOW / ASK / BLOCK
    - Optionally supports human approval for ASK
    - Logs a full, audit-friendly history for experiments / paper results
    """

    def __init__(self, goal: str, policy_mode: str = "balanced"):
        self.goal = goal
        self.monitor = TrustIntentMonitor()
        self.policy = get_policy(policy_mode)
        self.history: List[StepRecord] = []

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

    def run(
        self,
        proposed_actions: List[Dict[str, Any]],
        interactive: bool = True,
        auto_confirm: bool = False,
    ) -> List[StepRecord]:
        """
        proposed_actions: list of {"tool": "...", "args": {...}}

        auto_confirm:
          - False = ASK stops unless a human approves (safe default)
          - True  = treat ASK like ALLOW (debugging only)
        """
        for i, action in enumerate(proposed_actions, start=1):
            tool_name = str(action.get("tool", "")).strip()
            tool_args = action.get("args", {}) or {}

            # Convert history into simple dicts for the monitor (no StepRecord dependency)
            history_for_monitor = [
                {"tool": r.tool, "args": r.args, "decision": r.decision, "risk_score": r.risk_score}
                for r in self.history
            ]

            md: MonitorDecision = self.monitor.evaluate(
                goal=self.goal,
                tool_name=tool_name,
                tool_args=tool_args,
                history=history_for_monitor,
            )

            record = StepRecord(
                step=i,
                goal=self.goal,
                tool=tool_name,
                args=tool_args,
                decision=md.decision,
                reason=md.reason,
                risk_score=md.risk_score,
                tool_meta={},
                monitor_meta=md.metadata or {},
            )

            # -------------------------
            # Enforce decision: BLOCK
            # -------------------------
            if md.decision == "BLOCK":
                self.history.append(record)
                break

            # -------------------------
            # Enforce decision: ASK
            # -------------------------
            if md.decision == "ASK" and not auto_confirm:
                # Save the decision first (audit trail)
                self.history.append(record)

                if not interactive:
                    # Safe stop in non-interactive mode
                    break

                print("\n=== APPROVAL REQUIRED ===")
                print(f"Goal: {self.goal}")
                print(f"Proposed tool: {tool_name}")
                print(f"Arguments: {tool_args}")
                print(f"Risk score: {md.risk_score}")
                print(f"Reason: {md.reason}")
                choice = input("Approve this action? (y/n): ").strip().lower()

                if choice not in ("y", "yes"):
                    # Denied: stop safely
                    break

                # Approved: execute tool ONCE and update the last record
                # Strip monitor-only metadata before executing the tool
                exec_args = dict(tool_args)
                exec_args.pop("tainted", None)
                exec_args.pop("taint_sources", None)

                tool_result = self._execute_tool(tool_name, exec_args)
                last = self.history[-1]
                last.tool_ok = tool_result.ok
                last.tool_result = redact(tool_result.result, self.policy)
                last.tool_error = tool_result.error
                last.tool_meta = tool_result.meta or {}
                last.decision = "ALLOW"
                last.reason = f"{last.reason} (Approved by human)"

                # Move to next action (do NOT fall through and run again)
                continue

            # -------------------------
            # ALLOW (or ASK with auto_confirm)
            # -------------------------
            # Strip monitor-only metadata before executing the tool
            # Strip monitor-only metadata before executing the tool
            exec_args = dict(tool_args)
            exec_args.pop("tainted", None)
            exec_args.pop("taint_sources", None)

            tool_result = self._execute_tool(tool_name, exec_args)
            record.tool_ok = tool_result.ok
            record.tool_result = redact(tool_result.result, self.policy)
            record.tool_error = tool_result.error
            record.tool_meta = tool_result.meta or {}

            self.history.append(record)

        # Save full runtime trace to JSON
        save_run(self.history, self.goal)
        return self.history
