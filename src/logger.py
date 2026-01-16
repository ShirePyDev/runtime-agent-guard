from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, List


LOGS_DIR = Path(__file__).resolve().parents[1] / "logs"


def save_run(history: List[Any], goal: str) -> Path:
    """
    Save a full agent run (history) to a JSON file.
    Returns the path to the saved file.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = LOGS_DIR / f"run_{timestamp}.json"

    data = {
        "goal": goal,
        "steps": [step.__dict__ for step in history],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return path
