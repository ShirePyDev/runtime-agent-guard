from __future__ import annotations
from .classification import DataClassifier
from .signals import classify_sql_entities
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

import sqlglot
from sqlglot import exp


@dataclass(frozen=True)
class SqlRisk:
    level: str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: float        # 0.0 .. 1.0
    reason: str

    # Paper/audit-friendly metadata
    tables_hit: Tuple[str, ...] = field(default_factory=tuple)
    columns_hit: Tuple[str, ...] = field(default_factory=tuple)
    parsed_ok: bool = True
    bulk: bool = False


SENSITIVE_TABLES: Dict[str, float] = {
    "users": 0.8,
    "api_keys": 1.0,
}

SENSITIVE_COLUMNS: Dict[Tuple[str, str], float] = {
    ("users", "email"): 1.0,     # was 0.9
    ("api_keys", "api_key"): 1.0,
}

# If a column is sensitive but table can't be resolved, treat as medium risk
SENSITIVE_COLUMN_NAMES: Set[str] = {"email", "api_key", "password", "token"}


def extract_tables_and_columns(sql: str) -> tuple[Set[str], Set[Tuple[str, str]], bool]:
    tables: Set[str] = set()
    columns: Set[Tuple[str, str]] = set()

    try:
        # Match your runtime tool (sqlite3) to reduce parse errors
        tree = sqlglot.parse_one(sql, read="sqlite")
    except Exception:
        return set(), set(), False

    for t in tree.find_all(exp.Table):
        if t.name:
            tables.add(t.name.split(".")[-1].lower())

    for c in tree.find_all(exp.Column):
        col = (c.name or "").lower()
        tbl = (c.table or "").lower()
        if col:
            if tbl:
                columns.add((tbl.split(".")[-1], col))
            else:
                columns.add(("", col))

    return tables, columns, True


def is_select_without_limit(sql: str) -> bool:
    s = sql.strip().lower()
    return s.startswith("select") and (" limit " not in f" {s} ")


def assess_sql_risk(sql: str, goal_text: str) -> SqlRisk:
    tables, cols, parsed_ok = extract_tables_and_columns(sql)

    if not parsed_ok:
        return SqlRisk(
            level="MEDIUM",
            score=0.6,
            reason="Could not parse SQL reliably; confirm intent.",
            parsed_ok=False,
        )

    # Column-level sensitivity
    max_col_risk = 0.0
    sensitive_cols_hit: List[str] = []
    unresolved_sensitive_col = False

    for (tbl, col) in cols:
        if tbl and (tbl, col) in SENSITIVE_COLUMNS:
            r = SENSITIVE_COLUMNS[(tbl, col)]
            max_col_risk = max(max_col_risk, r)
            sensitive_cols_hit.append(f"{tbl}.{col}")
        elif not tbl and col in SENSITIVE_COLUMN_NAMES:
            unresolved_sensitive_col = True

    # Table-level sensitivity
    max_tbl_risk = 0.0
    sensitive_tables_hit: List[str] = []
    for t in tables:
        if t in SENSITIVE_TABLES:
            r = SENSITIVE_TABLES[t]
            max_tbl_risk = max(max_tbl_risk, r)
            sensitive_tables_hit.append(t)

    # Bulk query pattern
    bulk = is_select_without_limit(sql)
    bulk_risk = 0.7 if bulk and tables else 0.0

    # Aggregate risk
    risk = max(max_col_risk, max_tbl_risk, bulk_risk)

    # If unresolved sensitive column names exist, bump to MEDIUM unless already higher
    if unresolved_sensitive_col and risk < 0.6:
        risk = 0.6

    # Decide level
    if risk >= 1.0:
        return SqlRisk(
            level="CRITICAL",
            score=1.0,
            reason="Access to critical secrets table or column.",
            tables_hit=tuple(sorted(sensitive_tables_hit)),
            columns_hit=tuple(sorted(sensitive_cols_hit)),
            bulk=bulk,
        )

    if max_col_risk >= 0.9:
        cols_str = ", ".join(sensitive_cols_hit) if sensitive_cols_hit else "sensitive columns"
        return SqlRisk(
            level="HIGH",
            score=max_col_risk,
            reason=f"Sensitive columns accessed: {cols_str}",
            tables_hit=tuple(sorted(sensitive_tables_hit)),
            columns_hit=tuple(sorted(sensitive_cols_hit)),
            bulk=bulk,
        )

    if max_tbl_risk >= 0.8:
        tbls_str = ", ".join(sensitive_tables_hit) if sensitive_tables_hit else "sensitive tables"
        return SqlRisk(
            level="HIGH",
            score=max_tbl_risk,
            reason=f"Sensitive tables accessed: {tbls_str}",
            tables_hit=tuple(sorted(sensitive_tables_hit)),
            columns_hit=tuple(sorted(sensitive_cols_hit)),
            bulk=bulk,
        )

    if bulk:
        return SqlRisk(
            level="MEDIUM",
            score=0.7,
            reason="Bulk query pattern detected (SELECT without LIMIT).",
            tables_hit=tuple(sorted(sensitive_tables_hit)),
            columns_hit=tuple(sorted(sensitive_cols_hit)),
            bulk=True,
        )

    if unresolved_sensitive_col:
        return SqlRisk(
            level="MEDIUM",
            score=0.6,
            reason="Query references a potentially sensitive column but table could not be resolved.",
            tables_hit=tuple(sorted(sensitive_tables_hit)),
            columns_hit=tuple(sorted(sensitive_cols_hit)),
            bulk=bulk,
        )

    return SqlRisk(
        level="LOW",
        score=0.2,
        reason="No sensitive tables or columns detected.",
        tables_hit=tuple(sorted(sensitive_tables_hit)),
        columns_hit=tuple(sorted(sensitive_cols_hit)),
        bulk=bulk,
    )
