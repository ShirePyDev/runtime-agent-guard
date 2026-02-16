from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class ClassificationHit:
    kind: str  # "table" | "column" | "column_name"
    key: str   # e.g., "users" or "users.email" or "email"
    sensitivity: str
    score: float
    tags: Tuple[str, ...]


class DataClassifier:
    """
    Config-driven sensitivity registry.
    - Tables: "users" -> high/critical
    - Columns: "users.email" -> critical
    - Column name heuristics: "email" -> medium
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path(__file__).with_name("classification.json")
        self._cfg: Dict[str, Any] = {}
        self._tables: Dict[str, Dict[str, Any]] = {}
        self._cols: Dict[str, Dict[str, Any]] = {}
        self._col_name_heur: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        self._cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
        self._tables = {k.lower(): v for k, v in self._cfg.get("tables", {}).items()}
        self._cols = {k.lower(): v for k, v in self._cfg.get("columns", {}).items()}
        self._col_name_heur = {k.lower(): v for k, v in self._cfg.get("column_name_heuristics", {}).items()}

    def classify_table(self, table: str) -> Optional[ClassificationHit]:
        if not table:
            return None
        info = self._tables.get(table.lower())
        if not info:
            return None
        return ClassificationHit(
            kind="table",
            key=table.lower(),
            sensitivity=str(info.get("sensitivity", "low")),
            score=float(info.get("score", 0.0)),
            tags=tuple(info.get("tags", [])),
        )

    def classify_column(self, table: str, column: str) -> Optional[ClassificationHit]:
        if not column:
            return None
        key = f"{(table or '').lower()}.{column.lower()}".strip(".")
        info = self._cols.get(key)
        if not info:
            return None
        return ClassificationHit(
            kind="column",
            key=key,
            sensitivity=str(info.get("sensitivity", "low")),
            score=float(info.get("score", 0.0)),
            tags=tuple(info.get("tags", [])),
        )

    def classify_column_name(self, column: str) -> Optional[ClassificationHit]:
        if not column:
            return None
        info = self._col_name_heur.get(column.lower())
        if not info:
            return None
        return ClassificationHit(
            kind="column_name",
            key=column.lower(),
            sensitivity=str(info.get("sensitivity", "low")),
            score=float(info.get("score", 0.0)),
            tags=tuple(info.get("tags", [])),
        )
