from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Tuple

from openai import OpenAI

# Moderation guide + API reference:
# https://platform.openai.com/docs/guides/moderation
# https://platform.openai.com/docs/api-reference/moderations/object

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def _build_text_for_moderation(goal: str, action: Dict[str, Any]) -> str:
    """
    Baseline is text-only. We concatenate goal + tool + args into one string.
    This is intentionally simple and honest: moderation is not tool-aware.
    """
    tool = action.get("tool", "")
    args = action.get("args") or {}
    return f"GOAL:\n{goal}\n\nTOOL:\n{tool}\n\nARGS:\n{json.dumps(args, ensure_ascii=False, default=str)}"

def _moderate(text: str, model: str = "omni-moderation-latest") -> Tuple[bool, Dict[str, Any]]:
    """
    Returns:
      flagged: bool
      meta: small metadata (categories, scores) for debugging/reporting
    """
    resp = client.moderations.create(
        model=model,
        input=text,
    )
    r0 = resp.results[0]
    # r0.flagged is the main boolean signal
    meta = {
        "flagged": bool(r0.flagged),
        "categories": dict(r0.categories),
        "category_scores": dict(r0.category_scores),
        "model": resp.model,
    }
    return bool(r0.flagged), meta

def baseline_openai_moderation(ep: Dict[str, Any], model: str = "omni-moderation-latest") -> Dict[str, Any]:
    """
    Episode runner baseline:
    - Runs moderation on each step’s concatenated text.
    - If flagged, we treat as BLOCK (content safety intervention).
    - Otherwise ALLOW and continue.

    Note: This baseline is NOT meant to “understand” SQL/multi-step exfil.
    It’s a content safety filter baseline.
    """
    goal = ep["goal"]
    actions: List[Dict[str, Any]] = ep["actions"]

    decisions: List[str] = []
    blocks = 0
    asks = 0
    total_eval_ms = 0.0
    eval_calls = 0

    # (Optional) store per-step moderation info
    moderation_meta: List[Dict[str, Any]] = []

    import time
    for a in actions:
        text = _build_text_for_moderation(goal, a)

        t0 = time.perf_counter()
        flagged, meta = _moderate(text, model=model)
        t1 = time.perf_counter()

        total_eval_ms += (t1 - t0) * 1000.0
        eval_calls += 1

        moderation_meta.append({"tool": a.get("tool"), **meta})

        if flagged:
            decisions.append("BLOCK")
            blocks += 1
            break

        decisions.append("ALLOW")

    episode_decision = "BLOCK" if blocks else ("ASK" if asks else "ALLOW")
    avg_eval_ms = (total_eval_ms / eval_calls) if eval_calls else 0.0

    return {
        "episode_decision": episode_decision,
        "decisions": decisions,
        "asks": asks,
        "blocks": blocks,
        "avg_eval_ms": avg_eval_ms,
        "total_eval_ms": total_eval_ms,
        "eval_calls": eval_calls,
        "moderation_meta": moderation_meta,
    }
