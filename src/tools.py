from __future__ import annotations
from dotenv import load_dotenv
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = PROJECT_ROOT / "data" / "docs"
DB_PATH = PROJECT_ROOT / "data" / "db" / "app.db"
LOGS_DIR = PROJECT_ROOT / "logs"
EMAIL_LOG = LOGS_DIR / "email.log"
load_dotenv(PROJECT_ROOT / ".env")

@dataclass
class ToolResult:
    ok: bool
    result: Any = None
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)  # <-- NEW



def _ensure_logs_dir() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


# -------------------------
# Tool 1: search_docs(query)
# -------------------------
def search_docs(query: str, max_matches: int = 5) -> ToolResult:
    """
    Searches all text files under data/docs for lines matching the query.
    Returns small snippets (filename + line) so it's safe and easy to evaluate.
    """
    if not query or not query.strip():
        return ToolResult(ok=False, result=None, error="query is empty")

    q = query.strip().lower()
    matches: List[Dict[str, str]] = []

    if not DOCS_DIR.exists():
        return ToolResult(ok=False, result=None, error=f"docs directory not found: {DOCS_DIR}")

    for path in DOCS_DIR.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".txt", ".md"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                continue

            # Simple safe line-based search
            for i, line in enumerate(text.splitlines(), start=1):
                if q in line.lower():
                    matches.append({"file": str(path.relative_to(PROJECT_ROOT)), "line": f"{i}: {line.strip()}"})
                    if len(matches) >= max_matches:
                        return ToolResult(ok=True, result=matches)

    return ToolResult(ok=True, result=matches)


# ---------------------
# Tool 2: read_file(path)
# ---------------------
def read_file(path: str, max_chars: int = 2000) -> ToolResult:
    """
    Reads a file ONLY if it is inside data/docs.
    This prevents path traversal like ../../secrets.txt
    """
    if not path or not path.strip():
        return ToolResult(ok=False, result=None, error="path is empty")

    requested = (PROJECT_ROOT / path).resolve()

    # Enforce: requested must be inside DOCS_DIR
    try:
        requested.relative_to(DOCS_DIR.resolve())
    except ValueError:
        return ToolResult(
            ok=False,
            result=None,
            error=f"access denied: file must be under {DOCS_DIR.relative_to(PROJECT_ROOT)}",
        )

    if not requested.exists() or not requested.is_file():
        return ToolResult(ok=False, result=None, error="file not found")

    try:
        content = requested.read_text(encoding="utf-8", errors="ignore")
        return ToolResult(ok=True, result=content[:max_chars])
    except Exception as e:
        return ToolResult(ok=False, result=None, error=str(e))


# -------------------
# Tool 3: run_sql(query)
# -------------------
def run_sql(query: str, max_rows: int = 50) -> ToolResult:
    """
    Executes SQL against PostgreSQL using a read-only role (agent_ro).
    Limits rows returned to keep outputs safe.
    """
    if not query or not query.strip():
        return ToolResult(ok=False, result=None, error="query is empty")

    normalized = query.strip().lower()
    if not normalized.startswith("select"):
        return ToolResult(ok=False, result=None, error="only SELECT queries are allowed in this prototype")

    # Load env
    import os
    from dotenv import load_dotenv
    load_dotenv()

    db_kind = os.getenv("DB_KIND", "sqlite").lower()
    if db_kind != "postgres":
        return ToolResult(ok=False, result=None, error="DB_KIND is not 'postgres' (check your .env)")

    host = os.getenv("PG_HOST", "127.0.0.1")
    port = int(os.getenv("PG_PORT", "5432"))
    dbname = os.getenv("PG_DB", "agentdb")
    user = os.getenv("PG_USER", "agent_ro")
    password = os.getenv("PG_PASSWORD", "agentpass")

    try:
        import psycopg

        # Force LIMIT defensively if user forgot it
        q = query.strip().rstrip(";")
        if "limit" not in q.lower():
            q = f"{q} LIMIT {max_rows}"

        with psycopg.connect(host=host, port=port, dbname=dbname, user=user, password=password) as conn:
            with conn.cursor() as cur:
                cur.execute(q)
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()

        result = [dict(zip(cols, r)) for r in rows]
        return ToolResult(ok=True, result=result)

    except Exception as e:
        return ToolResult(ok=False, result=None, error=str(e))



# --------------------------------
# Tool 4: send_email(to, subject, body)
# --------------------------------
def send_email(to: str, subject: str, body: str) -> ToolResult:
    """
    MOCK email sender:
    Writes to logs/email.log instead of sending real email.
    This is perfect for security experiments (exfiltration attempts).
    """
    if not to or "@" not in to:
        return ToolResult(ok=False, result=None, error="invalid recipient")
    if subject is None:
        subject = ""
    if body is None:
        body = ""

    _ensure_logs_dir()

    timestamp = datetime.utcnow().isoformat() + "Z"
    entry = (
        f"---\n"
        f"time: {timestamp}\n"
        f"to: {to}\n"
        f"subject: {subject}\n"
        f"body:\n{body}\n"
    )

    try:
        EMAIL_LOG.write_text(EMAIL_LOG.read_text(encoding="utf-8") + entry, encoding="utf-8") if EMAIL_LOG.exists() else EMAIL_LOG.write_text(entry, encoding="utf-8")
        return ToolResult(ok=True, result={"logged_to": str(EMAIL_LOG.relative_to(PROJECT_ROOT))})
    except Exception as e:
        return ToolResult(ok=False, result=None, error=str(e))

def search_wikipedia(query: str, max_chars: int = 500) -> ToolResult:
    """
    Read-only Wikipedia lookup.
    - Returns the first paragraph only
    - Hard character limit
    - Marks output as tainted (untrusted external text)
    """
    if not query or not query.strip():
        return ToolResult(ok=False, result=None, error="query is empty")

    try:
        import wikipedia
        wikipedia.set_lang("en")

        page = wikipedia.page(query, auto_suggest=False)

        # First paragraph only
        summary = page.content.split("\n\n")[0].strip()

        # Hard limit
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "..."

        return ToolResult(
            ok=True,
            result={"title": page.title, "text": summary},
            meta={"tainted": True, "source": "wikipedia"},
        )

    except wikipedia.DisambiguationError as e:
        return ToolResult(
            ok=False,
            result=None,
            error=f"Ambiguous query. Options: {e.options[:5]}",
            meta={"tainted": True, "source": "wikipedia"},
        )

    except wikipedia.PageError:
        return ToolResult(
            ok=False,
            result=None,
            error="Page not found",
            meta={"tainted": True, "source": "wikipedia"},
        )

    except Exception as e:
        return ToolResult(
            ok=False,
            result=None,
            error=str(e),
            meta={"tainted": True, "source": "wikipedia"},
        )



# -------------------
# Simple tool registry
# -------------------
TOOLS = {
    "run_sql": run_sql,
    "send_email": send_email,
    "read_file": read_file,
    "search_docs": search_docs,
    "search_wikipedia": search_wikipedia,
}

