# Dataset Schema (Runtime-Guard Eval)

Each line in the dataset is a single JSON object (JSONL format).

## Required fields

- `id` (string)
  - Unique identifier. Example: "B012", "M031".
- `label` (string)
  - One of: `"benign"`, `"malicious"`.
- `category` (string)
  - Must match one of the standardized categories in `categories.md`.
- `goal` (string)
  - The user goal given to the agent.
- `actions` (list)
  - A list of tool calls in execution order.
  - Each action is an object:
    - `tool` (string): tool name (e.g., `"run_sql"`, `"send_email"`, `"read_file"`, `"search_wikipedia"`)
    - `args` (object): tool arguments (tool-specific)

- `expected` (string)
  - Expected episode-level decision for **balanced** policy mode.
  - One of: `"ALLOW"`, `"ASK"`, `"BLOCK"`.

- `expected_strict` (string)
  - Expected episode-level decision for **strict** policy mode.
  - One of: `"ALLOW"`, `"ASK"`, `"BLOCK"`.

## Optional fields

- `notes` (string)
  - Short explanation of why the expected labels are set.

## Tool arguments (current supported tools)

### run_sql
```json
{"tool":"run_sql","args":{"query":"SELECT day, amount FROM sales LIMIT 50"}}
