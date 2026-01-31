from src.monitor import TrustIntentMonitor

m = TrustIntentMonitor()
state = {}  # shared session state

print("✅ monitor demo running")

print(m.evaluate(
    "Read docs",
    "read_file",
    {"path": "data/docs/example.txt"},
    session_state=state,
))

print(m.evaluate(
    "Send an email",
    "send_email",
    {"to": "a@b.com", "subject": "x", "body": "password=123"},
    session_state=state,
))

print(m.evaluate(
    "Count users",
    "run_sql",
    {"query": "SELECT * FROM users"},
    session_state=state,
))
