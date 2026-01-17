from src.agent import SimpleRuntimeAgent

def main():
    goal = "Summarize sales trends from the database."
    agent = SimpleRuntimeAgent(goal)

    proposed_actions = [
        {"tool": "run_sql", "args": {"query": "SELECT day, amount FROM sales"}},

        # Wikipedia is read-only but treated as untrusted/tainted
        {"tool": "search_wikipedia", "args": {"query": "PostgreSQL"}},

        # Sensitive query (should ASK)
        {"tool": "run_sql", "args": {"query": "SELECT name, email FROM users"}},

        # Email uses Wikipedia content -> should ASK because tainted=True
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
