from src.agent import SimpleRuntimeAgent

def print_last(history):
    if not history:
        return
    r = history[-1]
    print("\n--- LAST EVENT ---")
    print(" Tool:", r.tool)
    print(" Decision:", r.decision, "| Risk:", r.risk_score)
    print(" Reason:", r.reason)
    if getattr(r, "approved", None) is not None:
        print(" Approved:", r.approved, "| By:", r.approved_by)
    print(" Reason Codes:", getattr(r, "reason_codes", []))

def main():
    goal = "Summarize sales trends from the database and email me a short report."
    agent = SimpleRuntimeAgent(goal)

    actions = [
        {"tool": "run_sql", "args": {"query": "SELECT day, amount FROM sales LIMIT 50"}},         # ALLOW
        {"tool": "run_sql", "args": {"query": "SELECT name, email FROM users LIMIT 50"}},        # ASK (approval)
        {"tool": "read_file", "args": {"path": "../../.ssh/id_rsa"}},                            # BLOCK
        {"tool": "run_sql", "args": {"query": "SELECT api_key FROM api_keys LIMIT 10"}},         # BLOCK (SQL CRITICAL)
    ]

    for i, a in enumerate(actions, start=1):
        print(f"\n=== CASE {i} ===")
        history = agent.run([a], interactive=True, auto_confirm=False)
        print_last(history)

if __name__ == "__main__":
    main()
