from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

DATASET_PATH = Path("eval/dataset.jsonl")

ALLOWED_LABELS = {"benign", "malicious"}
ALLOWED_DECISIONS = {"ALLOW", "ASK", "BLOCK"}

REQUIRED_TOP_FIELDS = {
    "id",
    "goal",
    "label",
    "actions",
    "expected",
    "expected_strict",
    "expected_auto",
    "expected_strict_auto",
}

ALLOWED_TOOLS = {"run_sql", "read_file", "send_email", "search_wikipedia", "search_docs"}


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception as e:
                raise RuntimeError(f"Invalid JSON on line {ln}: {e}") from e
    return rows


def normalize_decision(x: Any) -> str:
    s = str(x).strip().upper()
    if s in {"ALLOWED"}:
        return "ALLOW"
    if s in {"CONFIRM", "APPROVAL"}:
        return "ASK"
    if s in {"DENY", "BLOCKED"}:
        return "BLOCK"
    return s


def validate_episode(ep: Dict[str, Any], idx: int) -> List[str]:
    errors: List[str] = []
    missing = REQUIRED_TOP_FIELDS - set(ep.keys())
    if missing:
        errors.append(f"Missing top-level fields: {sorted(missing)}")

    ep_id = ep.get("id")
    if not ep_id or not isinstance(ep_id, str):
        errors.append("Field 'id' must be a non-empty string.")

    goal = ep.get("goal")
    if not goal or not isinstance(goal, str):
        errors.append("Field 'goal' must be a non-empty string.")

    label = ep.get("label")
    if label not in ALLOWED_LABELS:
        errors.append(f"Field 'label' must be one of {sorted(ALLOWED_LABELS)}.")

    # expected fields
    for k in ("expected", "expected_strict", "expected_auto", "expected_strict_auto"):
        v = ep.get(k)
        if v is None:
            errors.append(f"Missing field '{k}'.")
            continue
        nv = normalize_decision(v)
        if nv not in ALLOWED_DECISIONS:
            errors.append(f"Field '{k}' must be one of {sorted(ALLOWED_DECISIONS)} (got {v!r}).")

    # actions
    actions = ep.get("actions")
    if not isinstance(actions, list) or len(actions) == 0:
        errors.append("Field 'actions' must be a non-empty list.")
        return errors  # can't validate further

    for j, a in enumerate(actions):
        if not isinstance(a, dict):
            errors.append(f"Action[{j}] must be an object.")
            continue
        tool = a.get("tool")
        if tool not in ALLOWED_TOOLS:
            errors.append(f"Action[{j}].tool must be one of {sorted(ALLOWED_TOOLS)} (got {tool!r}).")
        args = a.get("args")
        if args is None:
            errors.append(f"Action[{j}].args is missing (should be an object).")
            continue
        if not isinstance(args, dict):
            errors.append(f"Action[{j}].args must be an object.")
            continue

        # tool-specific minimal schema checks
        if tool == "run_sql":
            if not isinstance(args.get("query"), str) or not args.get("query").strip():
                errors.append(f"Action[{j}] run_sql requires non-empty args.query.")
        elif tool == "read_file":
            if not isinstance(args.get("path"), str) or not args.get("path").strip():
                errors.append(f"Action[{j}] read_file requires non-empty args.path.")
        elif tool == "send_email":
            if not isinstance(args.get("to"), str) or "@" not in args.get("to", ""):
                errors.append(f"Action[{j}] send_email requires args.to containing '@'.")
            if not isinstance(args.get("subject", ""), str):
                errors.append(f"Action[{j}] send_email args.subject must be a string.")
            if not isinstance(args.get("body", ""), str):
                errors.append(f"Action[{j}] send_email args.body must be a string.")
            # optional flags (if present) must be valid
            if "tainted" in args and not isinstance(args["tainted"], bool):
                errors.append(f"Action[{j}] send_email args.tainted must be boolean if present.")
            if "taint_sources" in args and not isinstance(args["taint_sources"], list):
                errors.append(f"Action[{j}] send_email args.taint_sources must be list if present.")

    return errors


def summarize(data: List[Dict[str, Any]]) -> None:
    # Basic counts
    label_counts = Counter(ep.get("label") for ep in data)
    tool_counts = Counter()
    length_counts = Counter()
    expected_counts = Counter()
    expected_strict_counts = Counter()
    expected_auto_counts = Counter()
    expected_strict_auto_counts = Counter()

    for ep in data:
        actions = ep.get("actions") or []
        length_counts[len(actions)] += 1
        for a in actions:
            tool_counts[a.get("tool")] += 1

        expected_counts[normalize_decision(ep.get("expected"))] += 1
        expected_strict_counts[normalize_decision(ep.get("expected_strict"))] += 1
        expected_auto_counts[normalize_decision(ep.get("expected_auto"))] += 1
        expected_strict_auto_counts[normalize_decision(ep.get("expected_strict_auto"))] += 1

    print("\n=== DATASET SUMMARY ===")
    print(f"Total episodes: {len(data)}")
    print(f"Label counts: {dict(label_counts)}")
    print(f"Episode length distribution (#actions): {dict(length_counts)}")
    print(f"Tool usage: {dict(tool_counts)}")
    print(f"Expected (balanced/STOP) distribution: {dict(expected_counts)}")
    print(f"Expected_strict (strict/STOP) distribution: {dict(expected_strict_counts)}")
    print(f"Expected_auto (balanced/AUTO) distribution: {dict(expected_auto_counts)}")
    print(f"Expected_strict_auto (strict/AUTO) distribution: {dict(expected_strict_auto_counts)}")
    print("")


def main() -> None:
    if not DATASET_PATH.exists():
        raise RuntimeError(f"Dataset not found: {DATASET_PATH}")

    data = load_jsonl(DATASET_PATH)

    # Unique ID check
    ids = [ep.get("id") for ep in data]
    dupes = [k for k, v in Counter(ids).items() if v > 1 and k is not None]
    if dupes:
        print("❌ Duplicate IDs found:")
        for d in dupes[:20]:
            print(f"- {d}")
        raise SystemExit(1)

    # Validate episodes
    all_errors: List[Tuple[str, List[str]]] = []
    for i, ep in enumerate(data):
        errs = validate_episode(ep, i)
        if errs:
            all_errors.append((ep.get("id", f"<no-id-{i}>"), errs))

    if all_errors:
        print(f"❌ Validation failed: {len(all_errors)} episodes have issues.\n")
        # show first 25 episodes with errors
        for ep_id, errs in all_errors[:25]:
            print(f"[{ep_id}]")
            for e in errs:
                print(f"  - {e}")
            print("")
        raise SystemExit(1)

    print("✅ Dataset validation passed.")
    summarize(data)


if __name__ == "__main__":
    main()
