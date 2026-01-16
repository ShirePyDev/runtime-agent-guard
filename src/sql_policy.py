from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set, Tuple

import sqlglot
from sqlglot import exp


@dataclass(frozen=True)
class SqlRisk:
    level: str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: float        # 0..1
    reason: str


# Define which tables/columns are sensitive (you control this)
SENSITIVE_TABLES: Dict[str, float] = {
    "users": 0.8,
    "api_keys": 1.0,
}

SENSITIVE_COLUMNS: Dict[Tuple[str, str], float] = {
    ("users", "email"): 0.9,
    ("api_keys", "api_key"): 1.0,
}


def extract_tables_and_columns(sql: str) -> tuple[set[str], set[tuple[str, str]]]:
    """
    Parse SQL and extract referenced tables and columns.
    Returns:
      tables: {"sales", "users"}
      columns: {("users","email"), ("sales","amount")}
    """
    tables: Set[str] = set()
    columns: Set[Tuple[str, str]] = set()

    try:
        tree = sqlglot.parse_one(sql, read="postgres")
    except Exception:
        # If parse fails, return empty sets; monitor can ASK on parse failure.
        return set(), set()

    # Tables
    for t in tree.find_all(exp.Table):
        if t.name:
            tables.add(t.name.lower())

    # Columns (best effort)
    for c in tree.find_all(exp.Column):
        col = (c.name or "").lower()
        tbl = (c.table or "").lower()
        if col:
            if tbl:
                columns.add((tbl, col))
            else:
                # Unknown table (could be resolved later); store with empty table
                columns.add(("", col))

    return tables, columns


def is_bulk_query(sql: str) -> bool:
    """
    Detect risky broad queries like SELECT * with no LIMIT.
    Note: your tools already add LIMIT defensively, but this helps policy decisions.
    """
    s = sql.strip().lower()
    has_select_star = "select *" in s
    has_limit = " limit " in s or s.endswith(" limit")
    return has_select_star and not has_limit


def assess_sql_risk(sql: str, goal_text: str) -> SqlRisk:
    """
    Schema-aware risk scoring:
    - Sensitive tables/columns raise risk
    - Bulk queries raise risk
    """
    tables, cols = extract_tables_and_columns(sql)

    # If we can't parse, safer to ASK (unknown structure)
    if not tables and not cols:
        return SqlRisk("MEDIUM", 0.6, "Could not parse SQL reliably; confirm intent.")

    # Column sensitivity
    max_col_risk = 0.0
    col_reasons = []
    for (tbl, col) in cols:
        if tbl and (tbl, col) in SENSITIVE_COLUMNS:
            r = SENSITIVE_COLUMNS[(tbl, col)]
            max_col_risk = max(max_col_risk, r)
            col_reasons.append(f"{tbl}.{col}")

    # Table sensitivity
    max_tbl_risk = 0.0
    tbl_reasons = []
    for t in tables:
        if t in SENSITIVE_TABLES:
            r = SENSITIVE_TABLES[t]
            max_tbl_risk = max(max_tbl_risk, r)
            tbl_reasons.append(t)

    bulk = is_bulk_query(sql)
    bulk_risk = 0.7 if bulk else 0.0

    risk = max(max_col_risk, max_tbl_risk, bulk_risk)

    if risk >= 1.0:
        return SqlRisk("CRITICAL", 1.0, "Access to critical secrets table/column.")
    if risk >= 0.9:
        return SqlRisk("HIGH", risk, f"Sensitive columns accessed: {', '.join(col_reasons)}")
    if risk >= 0.8:
        return SqlRisk("HIGH", risk, f"Sensitive tables accessed: {', '.join(tbl_reasons)}")
    if bulk:
        return SqlRisk("MEDIUM", 0.7, "Bulk query pattern (SELECT * without LIMIT).")
    return SqlRisk("LOW", 0.2, "No sensitive tables/columns detected.")
