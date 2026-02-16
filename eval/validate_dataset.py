from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Update this to your current file
DATASET_PATH = Path("dataset_500.jsonl")  # or Path("eval/dataset_500.jsonl") if you store it there

ALLOWED_LABELS = {"benign", "malicious"}
ALLOWED_DECISIONS = {"ALLOW", "ASK", "BLOCK"}

REQUIRED_TOP_FIELDS = {
    "id",
    "goal",
    "label",
    "actions",
    "expected",
}

REQUIRED_EXPECTED_KEYS = {"balanced", "strict", "auto_confirm", "strict_auto"}

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
        return errors  # can't reliably validate more

    ep_id = ep.get("id")
    if not ep_id or not isinstance(ep_id, str):
        errors.append("Field 'id' must be a non-empty string.")

    goal = ep.get("goal")
    if not goal or not isinstance(goal, str):
        errors.append("Field 'goal' must be a non-empty string.")

    label = ep.get("label")
    if label not in ALLOWED_LABELS:
        errors.append(f"Field 'label' must be one of {sorted(ALLOWED_LABELS)}.")

    # expected dict schema
    expected = ep.get("expected")
    if not isinstance(expected, dict):
        errors.append("Field 'expected' must be an object with keys: balanced/strict/auto_confirm/strict_auto.")
    else:
        missing_keys = REQUIRED_EXPECTED_KEYS - set(expected.keys())
        if missing_keys:
            errors.append(f"'expected' missing keys: {sorted(missing_keys)}")

        # validate decision values
        for k in sorted(REQUIRED_EXPECTED_KEYS):
            v = expected.get(k)
            if v is None:
                errors.append(f"expected.{k} is missing.")
                continue
            nv = normalize_decision(v)
            if nv not in ALLOWED_DECISIONS:
                errors.append(
                    f"expected.{k} must be one of {sorted(ALLOWED_DECISIONS)} (got {v!r})."
                )

    # actions schema
    actions = ep.get("actions")
    if not isinstance(actions, list) or len(actions) == 0:
        errors.append("Field 'actions' must be a non-empty list.")
        return errors

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

        # tool-specific minimal checks
        if tool == "run_sql":
            if not isinstance(args.get("query"), str) or not args.get("query").strip():
                errors.append(f"Action[{j}] run_sql requires non-empty args.query.")
        elif tool == "read_file":
            if not isinstance(args.get("path"), str) or not args.get("path").strip():
                errors.append(f"Action[{j}] read_file requires non-empty args.path.")
        elif tool == "send_email":
            to = args.get("to", "")
            if not isinstance(to, str) or "@" not in to:
                errors.append(f"Action[{j}] send_email requires args.to containing '@'.")
            if not isinstance(args.get("subject", ""), str):
                errors.append(f"Action[{j}] send_email args.subject must be a string.")
            if not isinstance(args.get("body", ""), str):
                errors.append(f"Action[{j}] send_email args.body must be a string.")
            # optional flags
            if "tainted" in args and not isinstance(args["tainted"], bool):
                errors.append(f"Action[{j}] send_email args.tainted must be boolean if present.")
            if "taint_sources" in args and not isinstance(args["taint_sources"], list):
                errors.append(f"Action[{j}] send_email args.taint_sources must be list if present.")

    return errors


def summarize(data: List[Dict[str, Any]]) -> None:
    label_counts = Counter(ep.get("label") for ep in data)
    tool_counts = Counter()
    length_counts = Counter()

    expected_bal = Counter()
    expected_strict = Counter()
    expected_auto = Counter()
    expected_strict_auto = Counter()

    for ep in data:
        actions = ep.get("actions") or []
        length_counts[len(actions)] += 1
        for a in actions:
            tool_counts[a.get("tool")] += 1

        exp = ep.get("expected") or {}
        expected_bal[normalize_decision(exp.get("balanced"))] += 1
        expected_strict[normalize_decision(exp.get("strict"))] += 1
        expected_auto[normalize_decision(exp.get("auto_confirm"))] += 1
        expected_strict_auto[normalize_decision(exp.get("strict_auto"))] += 1

    print("\n=== DATASET SUMMARY ===")
    print(f"Total episodes: {len(data)}")
    print(f"Label counts: {dict(label_counts)}")
    print(f"Episode length distribution (#actions): {dict(length_counts)}")
    print(f"Tool usage: {dict(tool_counts)}")
    print(f"Expected balanced distribution: {dict(expected_bal)}")
    print(f"Expected strict distribution: {dict(expected_strict)}")
    print(f"Expected auto_confirm distribution: {dict(expected_auto)}")
    print(f"Expected strict_auto distribution: {dict(expected_strict_auto)}")
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
