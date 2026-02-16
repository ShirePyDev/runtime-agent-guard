from src.agent import SimpleRuntimeAgent

agent = SimpleRuntimeAgent(
    goal="Summarize what you found and email me a report.",
    policy_mode="balanced",
)

actions = [
    {"tool": "search_wikipedia", "args": {"query": "PostgreSQL"}},
    # IMPORTANT: do NOT pass tainted=True here
    {"tool": "send_email", "args": {
        "to": "test@example.com",
        "subject": "Summary",
        "body": "Here is a short summary."
    }},
]

agent.run(
    proposed_actions=actions,
    interactive=True,   # so you can SEE the approval prompt
    auto_confirm=False
)