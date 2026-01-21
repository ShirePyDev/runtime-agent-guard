from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set, Tuple

import sqlglot
from sqlglot import exp


# -------------------------------------------------------------------
# Risk object returned to the runtime monitor
# -------------------------------------------------------------------
@dataclass(frozen=True)
class SqlRisk:
    level: str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: float        # 0.0 .. 1.0
    reason: str         # human-readable explanation


# -------------------------------------------------------------------
# Sensitivity configuration (project-controlled)
# -------------------------------------------------------------------
# Table-level sensitivity
SENSITIVE_TABLES: Dict[str, float] = {
    "users": 0.8,
    "api_keys": 1.0,
}

# Column-level sensitivity (table, column)
SENSITIVE_COLUMNS: Dict[Tuple[str, str], float] = {
    ("users", "email"): 0.9,
    ("api_keys", "api_key"): 1.0,
}


# -------------------------------------------------------------------
# SQL parsing helpers
# -------------------------------------------------------------------
def extract_tables_and_columns(sql: str) -> tuple[Set[str], Set[Tuple[str, str]], bool]:
    """
    Parse SQL and extract referenced tables and columns.

    Returns:
      tables  : {"users", "sales"}
      columns : {("users","email"), ("sales","amount")}
      ok      : True if parsing succeeded, False otherwise
    """
    tables: Set[str] = set()
    columns: Set[Tuple[str, str]] = set()

    try:
        tree = sqlglot.parse_one(sql, read="postgres")
    except Exception:
        return set(), set(), False

    # Extract tables
    for t in tree.find_all(exp.Table):
        if t.name:
            # Strip schema if present (e.g., public.users → users)
            tables.add(t.name.split(".")[-1].lower())

    # Extract columns
    for c in tree.find_all(exp.Column):
        col = (c.name or "").lower()
        tbl = (c.table or "").lower()
        if col:
            if tbl:
                columns.add((tbl.split(".")[-1], col))
            else:
                columns.add(("", col))  # unresolved table

    return tables, columns, True


def is_select_without_limit(sql: str) -> bool:
    """
    Detect SELECT queries without LIMIT.
    Used as a bulk-data risk signal (not an automatic block).
    """
    s = sql.strip().lower()
    return s.startswith("select") and (" limit " not in f" {s} ")


# -------------------------------------------------------------------
# Main risk assessment entry point
# -------------------------------------------------------------------
def assess_sql_risk(sql: str, goal_text: str) -> SqlRisk:
    """
    Schema-aware SQL risk assessment.

    Design goals:
    - Deterministic and explainable
    - No SQL mutation (monitor decides ALLOW / ASK / BLOCK)
    - Safe default on uncertainty
    """
    tables, cols, parsed_ok = extract_tables_and_columns(sql)

    # Parsing failure → ASK (unknown structure)
    if not parsed_ok:
        return SqlRisk(
            level="MEDIUM",
            score=0.6,
            reason="Could not parse SQL reliably; confirm intent."
        )

    # ----------------------------------------------------------------
    # Column-level sensitivity
    # ----------------------------------------------------------------
    max_col_risk = 0.0
    sensitive_cols_hit = []

    for (tbl, col) in cols:
        if tbl and (tbl, col) in SENSITIVE_COLUMNS:
            r = SENSITIVE_COLUMNS[(tbl, col)]
            max_col_risk = max(max_col_risk, r)
            sensitive_cols_hit.append(f"{tbl}.{col}")

    # ----------------------------------------------------------------
    # Table-level sensitivity
    # ----------------------------------------------------------------
    max_tbl_risk = 0.0
    sensitive_tables_hit = []

    for t in tables:
        if t in SENSITIVE_TABLES:
            r = SENSITIVE_TABLES[t]
            max_tbl_risk = max(max_tbl_risk, r)
            sensitive_tables_hit.append(t)

    # ----------------------------------------------------------------
    # Bulk query pattern (SELECT without LIMIT)
    # ----------------------------------------------------------------
    bulk = is_select_without_limit(sql)
    bulk_risk = 0.7 if bulk and tables else 0.0

    # ----------------------------------------------------------------
    # Final risk aggregation
    # ----------------------------------------------------------------
    risk = max(max_col_risk, max_tbl_risk, bulk_risk)

    # CRITICAL: direct access to secrets
    if risk >= 1.0:
        return SqlRisk(
            level="CRITICAL",
            score=1.0,
            reason="Access to critical secrets table or column."
        )

    # HIGH: sensitive columns
    if max_col_risk >= 0.9:
        cols_str = ", ".join(sensitive_cols_hit) if sensitive_cols_hit else "sensitive columns"
        return SqlRisk(
            level="HIGH",
            score=max_col_risk,
            reason=f"Sensitive columns accessed: {cols_str}"
        )

    # HIGH: sensitive tables
    if max_tbl_risk >= 0.8:
        tbls_str = ", ".join(sensitive_tables_hit) if sensitive_tables_hit else "sensitive tables"
        return SqlRisk(
            level="HIGH",
            score=max_tbl_risk,
            reason=f"Sensitive tables accessed: {tbls_str}"
        )

    # MEDIUM: bulk data pattern
    if bulk:
        return SqlRisk(
            level="MEDIUM",
            score=0.7,
            reason="Bulk query pattern detected (SELECT without LIMIT)."
        )

    # LOW: no sensitive access
    return SqlRisk(
        level="LOW",
        score=0.2,
        reason="No sensitive tables or columns detected."
    )