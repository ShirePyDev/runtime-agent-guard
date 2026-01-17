from __future__ import annotations
from src.logger import save_run
from src.policy import get_policy, redact
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.monitor import TrustIntentMonitor, MonitorDecision
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


class SimpleRuntimeAgent:
    """
    Minimal agent runtime loop:
    - Accepts tool call proposals (for now: hardcoded list)
    - Calls the monitor BEFORE executing tools
    - Stores full history for later analysis (paper + experiments)
    """
class SimpleRuntimeAgent:
    def __init__(self, goal: str, policy_mode: str = "balanced"):
        self.goal = goal
        self.monitor = TrustIntentMonitor()
        self.history: List[StepRecord] = []

        # ✅ ADD THIS LINE (THIS IS WHAT YOU ASKED ABOUT)
        self.policy = get_policy(policy_mode)


    def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> ToolResult:
        tool_fn = TOOLS.get(tool_name)
        if tool_fn is None:
            return ToolResult(ok=False, result=None, error=f"Unknown tool: {tool_name}")
        return tool_fn(**tool_args)

    def run(
    self,
        proposed_actions: List[Dict[str, Any]],
        interactive: bool = True,
        auto_confirm: bool = False,
    ) -> List[StepRecord]:
        """
        proposed_actions: list of {"tool": "...", "args": {...}}
        auto_confirm:
          - False = ASK stops execution (safe default)
          - True  = treat ASK like ALLOW (useful for debugging only)
        """
        for i, action in enumerate(proposed_actions, start=1):
            tool_name = action["tool"]
            tool_args = action.get("args", {})

            # Convert StepRecord history into simple dicts for monitor
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
                tool_meta=tool_result.meta,   # <-- THIS IS STEP 3
            )


            # Enforce decision
            if md.decision == "BLOCK":
                self.history.append(record)
                break

            if md.decision == "ASK" and not auto_confirm:
                # Save the decision record first (so we always log what happened)
                self.history.append(record)

                if not interactive:
                    # In non-interactive mode, we stop safely on ASK
                    break

                # Ask the human for approval
                print("\n=== APPROVAL REQUIRED ===")
                print(f"Goal: {self.goal}")
                print(f"Proposed tool: {tool_name}")
                print(f"Arguments: {tool_args}")
                print(f"Risk score: {md.risk_score}")
                print(f"Reason: {md.reason}")
                choice = input("Approve this action? (y/n): ").strip().lower()

                if choice in ("y", "yes"):
                    # Execute tool after approval
                    tool_result = self._execute_tool(tool_name, tool_args)

                    # Update the last record with execution results
                    self.history[-1].tool_ok = tool_result.ok
                    self.history[-1].tool_result = tool_result.result
                    self.history[-1].tool_error = tool_result.error
                    self.history[-1].decision = "ALLOW"
                    self.history[-1].reason = self.history[-1].reason + " (Approved by human)"

            # If ALLOW (or ASK with auto_confirm), execute tool
            tool_result = self._execute_tool(tool_name, tool_args)
            record.tool_ok = tool_result.ok
            record.tool_result = redact(tool_result.result, self.policy)
            record.tool_error = tool_result.error

            self.history.append(record)

                # Save full runtime trace to JSON
        save_run(self.history, self.goal)
        return self.history

