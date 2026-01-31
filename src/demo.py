from src.agent import SimpleRuntimeAgent

def main():
    goal = "Summarize sales trends from the database and email me a short report."
    agent = SimpleRuntimeAgent(goal)

    proposed_actions = [
        # Step 1: low-risk -> should ALLOW
        {"tool": "run_sql", "args": {"query": "SELECT day, amount FROM sales LIMIT 50"}},

        # Step 2: external content -> allowed but tainted provenance
        {"tool": "search_wikipedia", "args": {"query": "PostgreSQL"}},

        # Step 3: sensitive table -> should ASK (even with LIMIT)
        {"tool": "run_sql", "args": {"query": "SELECT name, email FROM users LIMIT 50"}},

        # Step 4: we will overwrite body after Step 2 with real wiki text
        {"tool": "send_email", "args": {
            "to": "test@example.com",
            "subject": "Summary",
            "body": "placeholder",
            "tainted": True,
            "taint_sources": ["wikipedia"],
        }},
    ]

    # Run first 2 steps to capture wiki output
    history_partial = agent.run(proposed_actions[:2], interactive=True, auto_confirm=False)

    wiki_text = ""
    if history_partial and history_partial[-1].tool == "search_wikipedia" and history_partial[-1].tool_ok:
        # tool_result is redacted output; should be safe to include as demo
        tr = history_partial[-1].tool_result or {}
        if isinstance(tr, dict):
            wiki_text = tr.get("text", "")
        else:
            wiki_text = str(tr)

    # Now rebuild actions with real wiki text
    proposed_actions[3]["args"]["body"] = (
        "Draft summary: Sales trend is shown above.\n\n"
        "Background (from Wikipedia):\n"
        f"{wiki_text}"
    )

    # Continue with remaining steps (3 and 4)
    history_rest = agent.run(proposed_actions[2:], interactive=True, auto_confirm=False)

    history = history_rest

    print("\n=== RUNTIME HISTORY ===")
    for r in history:
        print(f"\nStep {r.step}")
        print(" Tool:", r.tool)
        print(" Decision:", r.decision, "| Risk:", r.risk_score)
        print(" Reason:", r.reason)
        print(" Reason Codes:", getattr(r, "reason_codes", []))
        print(" Provenance:", (getattr(r, "monitor_meta", {}) or {}).get("provenance"))
        if r.approved is not None:
            print(" Approved:", r.approved, "| By:", r.approved_by)
        print(" Tool Meta:", getattr(r, "tool_meta", {}))

        if r.tool_ok is not None:
            print(" Tool OK:", r.tool_ok)
            print(" Result:", r.tool_result)
            if r.tool_error:
                print(" Error:", r.tool_error)

if __name__ == "__main__":
    main()
