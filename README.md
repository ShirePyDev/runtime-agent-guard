# runtime-agent-guard

## Overview
**runtime-agent-guard** is a runtime security enforcement system for tool-using AI agents.  
It intercepts proposed tool actions and enforces explicit policy decisions (**ALLOW / ASK / BLOCK**) before any tool executes.

The system focuses on **runtime control, auditability, and least-privilege enforcement** rather than new language model development or prompt-level filtering.

---

## Architecture
The system operates as a guarded agent loop:

1. The agent proposes an action (tool name + arguments).
2. A runtime monitor evaluates intent alignment and tool-specific risk.
3. The decision is enforced:
   - **ALLOW**: tool executes immediately
   - **ASK**: human approval required
   - **BLOCK**: execution is stopped
4. Tool outputs are redacted if necessary and written to an audit log.

### Core Components
- `src/agent.py`: Minimal agent loop and enforcement logic
- `src/monitor.py`: Runtime trust and intent monitor
- `src/sql_policy.py`: Schema-aware SQL risk analysis using `sqlglot`
- `src/policy.py`: Policy profiles and output redaction
- `src/tools.py`: Tool implementations and registry
- `src/logger.py`: Runtime audit logging

---

## Security Design Principles
- **Runtime enforcement**: All tool calls are intercepted before execution.
- **Least privilege**: Database access uses a dedicated read-only role.
- **Defense in depth**: Independent protections at the monitor, tool, database, and output layers.
- **Human-in-the-loop**: High-impact actions require explicit approval.

---

## Tooling Overview
- **PostgreSQL** accessed via a read-only role (`agent_ro`) provisioned by `data/db/init.sql`
- **Schema-aware SQL security** using `sqlglot`, including:
  - Sensitive table detection (e.g., `users`, `api_keys`)
  - Column-level sensitivity (e.g., `users.email`, `api_keys.api_key`)
  - Bulk query detection
- **Mocked email sender** that logs to `logs/email.log`
- **Restricted file access** limited to `data/docs`

---

## Setup (Docker + PostgreSQL)

### Prerequisites
- Docker
- Python 3.x

### Start PostgreSQL
```bash
docker compose up -d
