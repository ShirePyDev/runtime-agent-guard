from src.monitor___2 import TrustIntentMonitor

monitor = TrustIntentMonitor()

result = monitor.evaluate("Show me the database schema")

print("Decision:", result.decision)
print("Reason:", result.reason)
print("Risk score:", result.risk_score)
print("Codes:", result.reason_codes)
