from src.agent import SimpleRuntimeAgent

def main():
    goal = "Summarize sales trends from the database."
    agent = SimpleRuntimeAgent(goal)

    proposed_actions = [
        # ✅ Step 1: low-risk (has LIMIT) -> should ALLOW
        {"tool": "run_sql", "args": {"query": "SELECT day, amount FROM sales LIMIT 50"}},

        {"tool": "search_wikipedia", "args": {"query": "PostgreSQL"}},

        # ✅ Step 3: sensitive table -> should ASK (even with LIMIT)
        {"tool": "run_sql", "args": {"query": "SELECT name, email FROM users LIMIT 50"}},

        # Step 4: tainted -> should ASK
        {"tool": "send_email", "args": {
            "to": "test@example.com",
            "subject": "Summary",
            "body": "Draft summary: Sales trend is shown above. Background: [WIKI_TEXT_HERE]",
            "tainted": True,
            "taint_sources": ["wikipedia"],
        }},
    ]

    history = agent.run(proposed_actions)

    print("\n=== RUNTIME HISTORY ===")
    for r in history:
        print(f"\nStep {r.step}")
        print(" Tool:", r.tool)
        print(" Decision:", r.decision, "| Risk:", r.risk_score)
        print(" Reason:", r.reason)
        print(" Tool Meta:", getattr(r, "tool_meta", {}))
        if r.tool_ok is not None:
            print(" Tool OK:", r.tool_ok)
            print(" Result:", r.tool_result)
            if r.tool_error:
                print(" Error:", r.tool_error)

if __name__ == "__main__":
    main()

