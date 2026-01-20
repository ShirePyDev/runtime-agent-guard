#!/usr/bin/env bash
set -euo pipefail

echo "=== runtime-agent-guard demo ==="
echo

echo "[1/3] Expect: ALLOW (read from allowed docs directory)"
python -m src.main --demo allow || true
echo

echo "[2/3] Expect: BLOCK (email contains credential/secret-like keywords)"
python -m src.main --demo block || true
echo

echo "[3/3] Expect: ASK (SQL SELECT without LIMIT)"
python -m src.main --demo ask || true
echo

echo "Done."

