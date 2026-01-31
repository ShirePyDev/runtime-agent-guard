from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv


# ---------------------------------------------------------------------
# Project paths + environment
# ---------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = (PROJECT_ROOT / "data" / "docs").resolve()
LOGS_DIR = (PROJECT_ROOT / "logs").resolve()
EMAIL_LOG = LOGS_DIR / "email.log"
DB_PATH = (PROJECT_ROOT / "data" / "db" / "app.db").resolve()

# Load .env once (consistent across tools). Safe even if file doesn't exist.
load_dotenv(PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------
# Tool result object (uniform across all tools)
# ---------------------------------------------------------------------
@dataclass
class ToolResult:
    ok: bool
    result: Any = None
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


def _ensure_logs_dir() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prov(source: str, tainted: bool, **extra: Any) -> Dict[str, Any]:
    """
    Standard provenance metadata so monitor + logger can reason about taint.
    """
    p = {"source": source, "tainted": bool(tainted)}
    p.update(extra)
    return {"provenance": p}


# ---------------------------------------------------------------------
# Tool 1: search_docs(query)
# ---------------------------------------------------------------------
def search_docs(query: str, max_matches: int = 5) -> ToolResult:
    """
    Searches .txt/.md files under data/docs for lines matching `query`.
    Returns small snippets (file + line number + line content).
    """
    if not query or not query.strip():
        return ToolResult(ok=False, error="query is empty", meta=_prov("docs", tainted=False))

    if not DOCS_DIR.exists():
        return ToolResult(ok=False, error=f"docs directory not found: {DOCS_DIR}", meta=_prov("docs", tainted=False))

    q = query.strip().lower()
    matches: List[Dict[str, str]] = []

    for path in DOCS_DIR.rglob("*"):
        if not (path.is_file() and path.suffix.lower() in {".txt", ".md"}):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for i, line in enumerate(text.splitlines(), start=1):
            if q in line.lower():
                matches.append(
                    {
                        "file": str(path.relative_to(PROJECT_ROOT)),
                        "line": f"{i}: {line.strip()}",
                    }
                )
                if len(matches) >= int(max_matches):
                    return ToolResult(ok=True, result=matches, meta=_prov("docs", tainted=False, match_count=len(matches)))

    return ToolResult(ok=True, result=matches, meta=_prov("docs", tainted=False, match_count=len(matches)))


# ---------------------------------------------------------------------
# Tool 2: read_file(path)
# ---------------------------------------------------------------------
def read_file(path: str, max_chars: int = 2000) -> ToolResult:
    """
    Reads a file ONLY if it is inside data/docs.
    Prevents traversal like ../../secrets.txt
    """
    if not path or not path.strip():
        return ToolResult(ok=False, error="path is empty", meta=_prov("file", tainted=False))

    raw = path.strip()

    # Allow either:
    # - "data/docs/example.txt"
    # - "example.txt" (interpreted relative to data/docs)
    candidate = (PROJECT_ROOT / raw).resolve()
    if not str(candidate).startswith(str(DOCS_DIR)):
        candidate = (DOCS_DIR / raw).resolve()

    # Enforce: candidate must be inside DOCS_DIR
    try:
        candidate.relative_to(DOCS_DIR)
    except ValueError:
        return ToolResult(
            ok=False,
            error=f"access denied: file must be under {DOCS_DIR.relative_to(PROJECT_ROOT)}",
            meta=_prov("file", tainted=True, resolved_path=str(candidate)),
        )

    if not candidate.exists() or not candidate.is_file():
        return ToolResult(ok=False, error="file not found", meta=_prov("file", tainted=False, resolved_path=str(candidate)))

    try:
        content = candidate.read_text(encoding="utf-8", errors="ignore")
        return ToolResult(
            ok=True,
            result=content[: int(max_chars)],
            meta=_prov("file", tainted=False, resolved_path=str(candidate), truncated=len(content) > int(max_chars)),
        )
    except Exception as e:
        return ToolResult(ok=False, error=str(e), meta=_prov("file", tainted=False, resolved_path=str(candidate)))


# ---------------------------------------------------------------------
# Tool 3: run_sql(query)
# ---------------------------------------------------------------------
def run_sql(query: str, max_rows: int = 50) -> ToolResult:
    """
    Executes READ-ONLY SQL against a local SQLite database.
    """
    if not query or not query.strip():
        return ToolResult(ok=False, error="query is empty", meta=_prov("db", tainted=False, db=str(DB_PATH)))

    q = query.strip().rstrip(";")
    if not q.lower().lstrip().startswith("select"):
        return ToolResult(ok=False, error="only SELECT queries are allowed", meta=_prov("db", tainted=False, db=str(DB_PATH)))

    # Defensive LIMIT (simple check)
    if "limit" not in q.lower():
        q = f"{q} LIMIT {int(max_rows)}"

    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            cur = conn.cursor()
            cur.execute(q)

            cols = [c[0] for c in (cur.description or [])]
            rows = cur.fetchmany(int(max_rows))

        result = [dict(zip(cols, r)) for r in rows]
        return ToolResult(
            ok=True,
            result=result,
            meta=_prov("db", tainted=False, row_count=len(result), db=str(DB_PATH)),
        )
    except Exception as e:
        return ToolResult(ok=False, error=str(e), meta=_prov("db", tainted=False, db=str(DB_PATH)))


# ---------------------------------------------------------------------
# Tool 4: send_email(to, subject, body)
# ---------------------------------------------------------------------
def send_email(to: str, subject: str, body: str) -> ToolResult:
    """
    MOCK email sender:
    Writes to logs/email.log instead of sending real email.
    """
    if not to or "@" not in to:
        return ToolResult(ok=False, error="invalid recipient", meta=_prov("egress", tainted=True, channel="email"))

    subject = subject or ""
    body = body or ""

    _ensure_logs_dir()

    entry = (
        f"---\n"
        f"time: {_utc_iso()}\n"
        f"to: {to}\n"
        f"subject: {subject}\n"
        f"body:\n{body}\n"
    )

    try:
        with EMAIL_LOG.open("a", encoding="utf-8") as f:
            f.write(entry)
        return ToolResult(
            ok=True,
            result={"logged_to": str(EMAIL_LOG.relative_to(PROJECT_ROOT))},
            meta={"provenance": {"source": "egress", "channel": "email"}},
        )
    except Exception as e:
        return ToolResult(ok=False, error=str(e), meta=_prov("egress", tainted=True, channel="email"))


# ---------------------------------------------------------------------
# Tool 5: search_wikipedia(query)
# ---------------------------------------------------------------------
def search_wikipedia(query: str, max_chars: int = 500) -> ToolResult:
    """
    Read-only Wikipedia lookup.
    - Returns the first paragraph only
    - Hard character limit
    - Marks output as tainted (untrusted external text)
    """
    meta = _prov("web", tainted=True, subsource="wikipedia")

    if not query or not query.strip():
        return ToolResult(ok=False, error="query is empty", meta=meta)

    try:
        import wikipedia

        wikipedia.set_lang("en")
        page = wikipedia.page(query.strip(), auto_suggest=False)
        summary = page.content.split("\n\n")[0].strip()

        if len(summary) > int(max_chars):
            summary = summary[: int(max_chars)] + "..."

        return ToolResult(ok=True, result={"title": page.title, "text": summary}, meta=meta)

    except Exception as e:
        # Keep it simple: treat all wiki failures as tainted web errors
        return ToolResult(ok=False, error=str(e), meta=meta)


# ---------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------
TOOLS: Dict[str, Callable[..., ToolResult]] = {
    "run_sql": run_sql,
    "send_email": send_email,
    "read_file": read_file,
    "search_docs": search_docs,
    "search_wikipedia": search_wikipedia,
}
