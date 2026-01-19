from src.monitor import TrustIntentMonitor

m = TrustIntentMonitor()
print("✅ monitor demo running")

print(m.evaluate("Read docs", "read_file", {"path": "data/docs/example.txt"}))
print(m.evaluate("Send an email", "send_email", {"to": "a@b.com", "subject": "x", "body": "password=123"}))
print(m.evaluate("Count users", "run_sql", {"query": "SELECT * FROM users"}))
