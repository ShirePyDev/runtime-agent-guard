# runtime-agent-guard

## Overview
runtime-agent-guard is a runtime security enforcement system for tool-using AI agents. It intercepts proposed tool actions and enforces policy decisions (ALLOW / ASK / BLOCK) before any tool executes. The focus is on runtime controls, auditability, and least-privilege access rather than new model development.

## Architecture
The system runs a simple agent loop that routes every proposed action through a monitor before executing tools:

1. Agent proposes an action (tool name + arguments).
2. Monitor evaluates intent drift and tool-specific risk.
3. Decision is enforced: ALLOW executes, ASK requires human approval, BLOCK stops execution.
4. Results are redacted and a full audit log is written.

Key components:
- `src/agent.py`: Minimal agent loop and enforcement.
- `src/monitor.py`: Trust/intent monitor with rule-based decisions and risk scoring.
- `src/sql_policy.py`: Schema-aware SQL risk analysis using `sqlglot`.
- `src/policy.py`: Redaction and policy profiles.
- `src/tools.py`: Tool implementations and registry.
- `src/logger.py`: Runtime audit log writer.

## Security Design Principles
- Runtime enforcement: tool calls are intercepted and evaluated before execution.
- Least privilege: database access uses a dedicated read-only role.
- Defense in depth: policy checks at multiple layers (monitor rules, tool constraints, database role, output redaction, audit logging).
- Human-in-the-loop: ASK decisions require explicit approval for high-impact actions.

## Tooling Overview
- PostgreSQL access with a read-only role (`agent_ro`) provisioned by `data/db/init.sql`.
- Schema-aware SQL checks with `sqlglot`, including sensitive table/column detection (e.g., `users.email`, `api_keys.api_key`) and bulk query detection.
- Mocked email sender that logs to `logs/email.log` instead of sending.
- File access and search restricted to `data/docs`.

## Setup (Docker + PostgreSQL)
Prerequisites: Docker, Python 3.x

1. Start PostgreSQL:

```bash
docker compose up -d
```

2. Create a `.env` file in the repo root:

```bash
DB_KIND=postgres
PG_HOST=127.0.0.1
PG_PORT=5432
PG_DB=agentdb
PG_USER=agent_ro
PG_PASSWORD=agentpass
```

3. Install Python dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Example Workflow
Run the demo to see ALLOW, ASK, and BLOCK decisions in action:

```bash
python src/demo.py
```

The demo proposes:
- A safe sales query (ALLOW).
- A query touching `users` (ASK).
- An email send after approval (ALLOW if approved).

Runtime traces are written to `logs/run_*.json`, and email output is logged to `logs/email.log`.

## Evaluation Philosophy
Decisions are explicit and auditable:
- ALLOW: low risk or policy-approved.
- ASK: higher impact or sensitive access that requires human approval.
- BLOCK: unsafe or clearly out-of-scope actions.

Risk scores are attached to each decision to support analysis and future policy tuning.

## Research Positioning
This project explores runtime security for agentic AI systems that use external tools. It is model-agnostic: the guard sits between the agent and tools and can be used with any planner or LLM. The emphasis is on enforceable, testable security controls rather than claims about alignment or safety guarantees.

## Roadmap
- Expand policy coverage for additional tools and data sources.
- Improve SQL parsing robustness and schema resolution.
- Add richer audit formats and analysis utilities.
- Integrate configurable policy profiles and test suites.
- Evaluate against a larger library of adversarial and benign tasks.

## Repository Layout
- `src/`: agent, monitor, policies, tools, and evaluation scripts.
- `data/`: demo docs and database initialization.
- `logs/`: audit traces and mock email output.
- `docker-compose.yml`: local PostgreSQL service.

## License
Apache License 2.0. See `LICENSE`.
