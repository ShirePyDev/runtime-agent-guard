# src/signals.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import re


def _clip01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


# Tool/operation priors (lightweight, tune later)
TOOL_PRIOR: Dict[str, float] = {
    "run_sql": 0.25,
    "read_file": 0.10,
    "search_docs": 0.05,
    "search_wikipedia": 0.05,
    "send_email": 0.40,
}

OP_PRIOR: Dict[str, float] = {
    "read": 0.05,
    "query": 0.15,
    "search": 0.05,
    "send": 0.30,
    "unknown": 0.10,
}


@dataclass
class RiskSignals:
    tool_name: str
    operation: str  # "read" | "query" | "send" | "search" | "unknown"
    goal: str

    # Resource references
    tables: List[str] = field(default_factory=list)
    columns: List[Tuple[str, str]] = field(default_factory=list)

    # Derived detections
    sensitivity_hits: List[object] = field(default_factory=list)  # keep your real type if you have it
    bulk_indicator: bool = False
    missing_limit: bool = False

    # Provenance / context
    tainted_input: bool = False
    goal_alignment: Optional[float] = None  # can fill later

    # Numeric summary
    base_score: float = 0.0
    reasons: List[str] = field(default_factory=list)

    def finalize(self) -> None:
        """
        Deterministic risk aggregation from extracted signals.
        Keeps it simple + conservative (good for security and papers).
        """
        reasons: List[str] = []

        x_sens = 1.0 if self.sensitivity_hits else 0.0
        x_bulk = 1.0 if self.bulk_indicator else 0.0
        x_nolimit = 1.0 if self.missing_limit else 0.0
        x_taint = 1.0 if self.tainted_input else 0.0

        tool_prior = TOOL_PRIOR.get(self.tool_name, 0.15)
        op_prior = OP_PRIOR.get(self.operation, 0.10)

        # weights (tune later with eval/)
        w_sens, w_bulk, w_nolimit, w_taint = 0.70, 0.35, 0.30, 0.45
        w_tool, w_op = 0.20, 0.15

        severe = (
            w_sens * x_sens +
            w_bulk * x_bulk +
            w_nolimit * x_nolimit +
            w_taint * x_taint
        )
        severe = _clip01(severe)
        score = _clip01(severe + (w_tool * tool_prior) + (w_op * op_prior))

        if x_sens:
            reasons.append("Sensitive data detected (classification hits).")
        if x_bulk:
            reasons.append("Bulk extraction indicator detected.")
        if x_nolimit:
            reasons.append("Query missing LIMIT (potential bulk access).")
        if x_taint:
            reasons.append("Tainted input / possible prompt injection.")
        if tool_prior >= 0.35:
            reasons.append(f"High-risk tool prior: {self.tool_name}.")
        if self.operation == "send":
            reasons.append("High-risk operation: send.")

        self.base_score = score
        self.reasons = reasons


# -------------------------
# SQL entity extraction
# -------------------------

_SQL_FROM_JOIN_RE = re.compile(
    r"""
    (?:
        \bfrom\b
      | \bjoin\b
      | \bupdate\b
      | \binto\b
      | \bdelete\s+from\b
    )
    \s+
    (?P<table>[a-zA-Z_][\w\.]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_SQL_SELECT_RE = re.compile(
    r"""
    \bselect\b
    (?P<select>.*?)
    \bfrom\b
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_SQL_LIMIT_RE = re.compile(r"\blimit\b\s+\d+", re.IGNORECASE)


@dataclass
class SqlEntities:
    """
    Return type for classify_sql_entities().

    Compatible with:
      tables, columns = classify_sql_entities(sql)

    AND also:
      ent = classify_sql_entities(sql)
      ent.missing_limit, ent.bulk_indicator, ...
    """
    tables: List[str]
    columns: List[Tuple[str, str]]
    missing_limit: bool
    bulk_indicator: bool

    def __iter__(self):
        # Allows unpacking into (tables, columns)
        yield self.tables
        yield self.columns


def _extract_tables(sql: str) -> List[str]:
    tables: List[str] = []
    for m in _SQL_FROM_JOIN_RE.finditer(sql):
        t = m.group("table")
        if t:
            tables.append(t)
    # unique but keep order
    seen = set()
    out = []
    for t in tables:
        key = t.lower()
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


def _extract_columns(sql: str) -> List[Tuple[str, str]]:
    """
    Best-effort extraction of selected columns.
    Returns list of (table_or_alias, column) when possible, else ("", col).
    """
    m = _SQL_SELECT_RE.search(sql)
    if not m:
        return []

    select_part = m.group("select").strip()
    if not select_part:
        return []

    # Handle SELECT * quickly
    if select_part == "*":
        return [("", "*")]

    # Split by commas at top-level (best-effort; no deep SQL parsing)
    raw_cols = [c.strip() for c in select_part.split(",") if c.strip()]
    cols: List[Tuple[str, str]] = []

    for c in raw_cols:
        # remove aliases: "col as x" or "col x"
        c = re.split(r"\bas\b", c, flags=re.IGNORECASE)[0].strip()
        c = c.split() [0].strip() if c else c  # keep first token as best-effort

        # remove simple function wrapping like COUNT(col)
        c = re.sub(r"^[A-Z_]+\((.*)\)$", r"\1", c, flags=re.IGNORECASE).strip()

        if "." in c:
            left, right = c.split(".", 1)
            cols.append((left.strip(), right.strip()))
        else:
            cols.append(("", c.strip()))

    # unique preserve order
    seen = set()
    out = []
    for t, col in cols:
        key = (t.lower(), col.lower())
        if key not in seen:
            seen.add(key)
            out.append((t, col))
    return out


def _has_limit(sql: str) -> bool:
    return _SQL_LIMIT_RE.search(sql) is not None


def _bulk_indicator(sql: str) -> bool:
    """
    Heuristic bulk signals:
      - SELECT * from table without LIMIT
      - LIMIT very large (optional; we treat missing LIMIT as main signal)
    """
    s = sql.strip().lower()
    if "select" in s and "from" in s:
        # SELECT * with no LIMIT is often bulk
        if re.search(r"\bselect\b\s+\*\s+\bfrom\b", s) and not _has_limit(s):
            return True
    return False


# -------------------------------------------------
# SQL Parsing (extract tables + columns from query)
# -------------------------------------------------

def parse_sql_entities(sql: str):
    """
    Extract tables + columns from SQL query.
    Used internally by monitor before classification.
    """
    tables = _extract_tables(sql)
    columns = _extract_columns(sql)
    missing_limit = not _has_limit(sql) if re.search(r"\bselect\b", sql, re.IGNORECASE) else False
    bulk = _bulk_indicator(sql)
    return tables, columns, missing_limit, bulk


# -------------------------------------------------
# Sensitivity Classification (EXPECTED BY MONITOR)
# -------------------------------------------------

def classify_sql_entities(classifier, tables, columns):
    """
    Expected signature by monitor.py:
        classify_sql_entities(classifier, tables, columns)

    Returns a list of classification hits.
    """

    hits = []

    if classifier is None:
        return hits

    # Classify tables
    for t in tables:
        result = classifier.classify_table(t)
        if result:
            hits.append(result)

    # Classify columns
    for table, column in columns:
        result = classifier.classify_column(table, column)
        if result:
            hits.append(result)

    return hits

