from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


LOGS_DIR = Path(__file__).resolve().parents[1] / "logs"
SCHEMA_VERSION = "runtime_agent_guard.v1"


def _json_safe(obj):
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, tuple):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, set):
        return sorted([_json_safe(v) for v in obj])
    return obj



def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _serialize_step(step: Any) -> Dict[str, Any]:
    """
    Explicit, stable serialization of a StepRecord.
    Avoids relying on __dict__ implicitly.
    """
    return {
        "step": step.step,
        "goal": step.goal,
        "tool": step.tool,
        "args": step.args,

        "decision": step.decision,
        "reason": step.reason,
        "risk_score": step.risk_score,
        "reason_codes": step.reason_codes,

        "approved": step.approved,
        "approved_by": step.approved_by,

        "tool_ok": step.tool_ok,
        "tool_result": step.tool_result,
        "tool_error": step.tool_error,
        "tool_meta": step.tool_meta,

        "monitor_meta": step.monitor_meta,
    }


def _aggregate_run(history: List[Any]) -> Dict[str, Any]:
    """
    Produce run-level safety statistics (paper-friendly).
    """
    if not history:
        return {
            "steps": 0,
            "max_risk": 0.0,
            "blocked": False,
            "asks": 0,
            "allows": 0,
            "approvals": 0,
        }

    max_risk = max((s.risk_score or 0.0) for s in history)
    decisions = [s.decision for s in history]

    return {
        "steps": len(history),
        "max_risk": round(float(max_risk), 3),
        "blocked": "BLOCK" in decisions,
        "asks": decisions.count("ASK"),
        "allows": decisions.count("ALLOW"),
        "approvals": sum(1 for s in history if getattr(s, "approved", False)),
    }


def save_run(
    history: List[Any],
    goal: str,
    *,
    policy_mode: str | None = None,
    session_state: Dict[str, Any] | None = None,
) -> Path:
    """
    Save a full runtime_agent_guard execution trace.

    Returns:
        Path to the saved JSON file.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = LOGS_DIR / f"run_{timestamp}.json"

    steps = [_serialize_step(step) for step in history]
    summary = _aggregate_run(history)

    data = {
        "schema": SCHEMA_VERSION,
        "run_id": path.stem,
        "timestamp_utc": _utc_iso(),

        "goal": goal,
        "policy_mode": policy_mode,
        "session_state": session_state or {},

        "summary": summary,
        "steps": steps,
    }

    with path.open("w", encoding="utf-8") as f:
        json.dump(_json_safe(data), f, indent=2, ensure_ascii=False)

    return path
