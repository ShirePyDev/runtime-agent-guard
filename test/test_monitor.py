import pytest

from src.monitor import TrustIntentMonitor


# -------------------------
# Helper: stub SQL risk obj
# -------------------------
class _FakeRisk:
    def __init__(self, level: str, score: float = 0.5, reason: str = "stub"):
        self.level = level
        self.score = score
        self.reason = reason


# -------------------------
# Fixture: monitor instance
# -------------------------
@pytest.fixture()
def monitor(tmp_path):
    """
    We pass a temporary allowed docs directory so tests don't depend on
    your real filesystem. This makes tests stable on any machine/CI.
    """
    allowed_docs = tmp_path / "data" / "docs"
    allowed_docs.mkdir(parents=True, exist_ok=True)

    # Create an example doc file inside the allowed directory
    (allowed_docs / "example.txt").write_text("hello", encoding="utf-8")

    # Important: monitor uses resolve() checks, so we pass the real path
    m = TrustIntentMonitor(allowed_docs_dir=str(allowed_docs))
    return m


# 1) read_file allows data/docs/x.txt (inside allowed base)
def test_read_file_allow_inside_allowed_dir(monitor, tmp_path):
    allowed_docs = tmp_path / "data" / "docs"
    path = allowed_docs / "example.txt"

    d = monitor.evaluate(
        goal="Read a document",
        tool_name="read_file",
        tool_args={"path": str(path)},
        history=[],
    )
    assert d.decision == "ALLOW"
    assert "FILE_ALLOWED" in d.reason_codes


# 2) read_file blocks path traversal attempt (../)
def test_read_file_blocks_traversal(monitor, tmp_path):
    allowed_docs = tmp_path / "data" / "docs"
    outside = tmp_path / "secrets.txt"
    outside.write_text("secret", encoding="utf-8")

    # This path tries to escape docs using ../
    traversal = allowed_docs / ".." / "secrets.txt"

    d = monitor.evaluate(
        goal="Read a document",
        tool_name="read_file",
        tool_args={"path": str(traversal)},
        history=[],
    )
    assert d.decision == "BLOCK"
    assert "FILE_OUTSIDE_ALLOWED_DIR" in d.reason_codes


# 3) send_email blocks credential-like keywords
@pytest.mark.parametrize("body", [
    "Here is my password: 1234",
    "My api key is sk-abcdef1234567890",
    "use this token=XYZ123",
])
def test_send_email_blocks_secrets(monitor, body):
    d = monitor.evaluate(
        goal="Send an email summary to my professor",
        tool_name="send_email",
        tool_args={"to": "a@b.com", "subject": "hi", "body": body},
        history=[],
    )
    assert d.decision == "BLOCK"
    assert "EMAIL_CONTAINS_SECRETS" in d.reason_codes


# 4) send_email asks when tainted=True
def test_send_email_asks_when_tainted(monitor):
    d = monitor.evaluate(
        goal="Send an email summary to my professor",
        tool_name="send_email",
        tool_args={
            "to": "a@b.com",
            "subject": "summary",
            "body": "This text came from wikipedia",
            "tainted": True,
            "taint_sources": ["wikipedia"],
        },
        history=[],
    )
    assert d.decision == "ASK"
    assert "EMAIL_TAINTED_CONTENT" in d.reason_codes


# 5) send_email blocks for exfil phrases
@pytest.mark.parametrize("body", [
    "Please send everything, entire database.",
    "Here is the full user list.",
    "dump users and export users now",
])
def test_send_email_blocks_exfil_phrases(monitor, body):
    d = monitor.evaluate(
        goal="Send an email update",
        tool_name="send_email",
        tool_args={"to": "a@b.com", "subject": "data", "body": body},
        history=[],
    )
    assert d.decision == "BLOCK"
    assert "EMAIL_EXFIL_PATTERN" in d.reason_codes


# 6) send_email asks if email not clearly requested in goal
def test_send_email_asks_if_not_in_goal(monitor):
    d = monitor.evaluate(
        goal="Summarize the docs about SQL injection",  # no "email" or "send"
        tool_name="send_email",
        tool_args={"to": "a@b.com", "subject": "summary", "body": "short summary"},
        history=[],
    )
    assert d.decision == "ASK"
    assert "EMAIL_NOT_IN_GOAL" in d.reason_codes


# -------------------------
# SQL tests (monkeypatch)
# -------------------------
def test_run_sql_blocks_on_critical(monitor, monkeypatch):
    # Patch assess_sql_risk to return CRITICAL
    from src import monitor as monitor_module

    monkeypatch.setattr(
        monitor_module,
        "assess_sql_risk",
        lambda query, goal: _FakeRisk("CRITICAL", 0.99, "critical risk"),
    )

    d = monitor.evaluate(
        goal="Check user stats",
        tool_name="run_sql",
        tool_args={"query": "DROP TABLE users;"},
        history=[],
    )
    assert d.decision == "BLOCK"
    assert "SQL_CRITICAL" in d.reason_codes


def test_run_sql_asks_on_high_or_medium(monitor, monkeypatch):
    from src import monitor as monitor_module

    monkeypatch.setattr(
        monitor_module,
        "assess_sql_risk",
        lambda query, goal: _FakeRisk("HIGH", 0.8, "touches sensitive columns"),
    )

    d = monitor.evaluate(
        goal="Check user stats",
        tool_name="run_sql",
        tool_args={"query": "SELECT email FROM users LIMIT 10;"},
        history=[],
    )
    assert d.decision == "ASK"
    assert "SQL_HIGH" in d.reason_codes


# 9) run_sql asks for SELECT without LIMIT (even if low risk)
def test_run_sql_asks_when_select_missing_limit(monitor, monkeypatch):
    from src import monitor as monitor_module

    monkeypatch.setattr(
        monitor_module,
        "assess_sql_risk",
        lambda query, goal: _FakeRisk("LOW", 0.2, "low risk"),
    )

    d = monitor.evaluate(
        goal="Count users",
        tool_name="run_sql",
        tool_args={"query": "SELECT * FROM users"},
        history=[],
    )
    assert d.decision == "ASK"
    assert "SQL_MISSING_LIMIT" in d.reason_codes


# 10) unknown tool -> ASK
def test_unknown_tool_asks(monitor):
    d = monitor.evaluate(
        goal="Do something",
        tool_name="delete_files_forever",
        tool_args={"path": "/"},
        history=[],
    )
    assert d.decision == "ASK"
    assert "UNKNOWN_TOOL" in d.reason_codes
