from src.agent import SimpleRuntimeAgent

def main():
    goal = "Summarize sales trends from the database."
    agent = SimpleRuntimeAgent(goal)

    proposed_actions = [
        {"tool": "run_sql", "args": {"query": "SELECT day, amount FROM sales"}},

        # This should trigger ASK (users table touched but goal doesn't mention users)
        {"tool": "run_sql", "args": {"query": "SELECT name, email FROM users"}},

        # Only runs if you approve ASK
        {"tool": "send_email", "args": {"to": "test@example.com", "subject": "Summary", "body": "Here is the sales summary."}},
    ]


    history = agent.run(proposed_actions)

    print("\n=== RUNTIME HISTORY ===")
    for r in history:
        print(f"\nStep {r.step}")
        print(" Tool:", r.tool)
        print(" Decision:", r.decision, "| Risk:", r.risk_score)
        print(" Reason:", r.reason)
        if r.tool_ok is not None:
            print(" Tool OK:", r.tool_ok)
            print(" Result:", r.tool_result)
            if r.tool_error:
                print(" Error:", r.tool_error)

if __name__ == "__main__":
    main()
