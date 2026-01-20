# runtime-agent-guard

## Overview

- **runtime-agent-guard** is a runtime security enforcement system for **tool-using AI agents**
- It intercepts proposed tool actions and enforces explicit policy decisions:
  - **ALLOW**
  - **ASK**
  - **BLOCK**
- Decisions are enforced **before any tool execution**
- The system focuses on:
  - Runtime control of agent behavior
  - Auditable and inspectable decisions
  - Least-privilege access to external systems
  - Human-in-the-loop safety for high-risk actions
- Designed for **research, experimentation, and demonstration** of trust-aware agent execution

---

## Key Features

- Runtime interception of all agent tool calls
- Explicit policy decisions (**ALLOW / ASK / BLOCK**)
- Schema-aware SQL risk analysis
- Sensitive content detection for email actions
- Restricted filesystem access
- Centralized audit logging
- Modular and extensible architecture

## 🚀 Quick Start

### Clone the repository

- git clone https://github.com/ShirePyDev/runtime-agent-guard.git
- cd runtime-agent-guard

## System Architecture

- The system is implemented as a **guarded agent execution loop**
- All agent actions are intercepted by a runtime guard before execution
- The guard operates independently from the underlying language model

### Execution Flow

- **Agent Proposal**
  - The agent proposes an action consisting of:
    - Tool name
    - Tool arguments

- **Runtime Monitoring**
  - A runtime monitor evaluates:
    - Intent alignment
    - Tool-specific risk
    - Policy constraints

- **Policy Decision**
  - One of three decisions is produced:
    - **ALLOW** — action is safe and executed immediately
    - **ASK** — action requires explicit human approval
    - **BLOCK** — action is unsafe and execution is prevented

- **Execution and Logging**
  - Allowed actions execute under restricted permissions
  - Tool outputs are optionally redacted
  - All decisions and metadata are written to audit logs

- This design ensures unsafe or ambiguous actions are stopped **before real-world side effects occur**

---

## Core Components

- `src/agent.py`
  - Minimal agent loop
  - Enforces runtime guard decisions

- `src/monitor.py`
  - Runtime trust, intent, and risk monitoring
  - Triggers policy rules

- `src/sql_policy.py`
  - Schema-aware SQL risk analysis using `sqlglot`
  - Detects:
    - Sensitive tables
    - Sensitive columns
    - Bulk or unbounded queries

- `src/policy.py`
  - Central policy definitions
  - Decision thresholds
  - Output redaction rules

- `src/tools.py`
  - Tool implementations
  - Centralized tool registry

- `src/logger.py`
  - Runtime audit logging
  - Records decisions, actions, and metadata

- The codebase is intentionally modular to support experimentation and extension

---

## Security Design Principles

- **Runtime enforcement**
  - All tool calls are intercepted before execution

- **Least privilege**
  - External systems (e.g., databases) are accessed using restricted, read-only roles

- **Defense in depth**
  - Independent protections across:
    - Monitoring
    - Tool logic
    - Database access
    - Output handling

- **Human-in-the-loop**
  - High-impact or ambiguous actions require explicit approval

---

## Tooling Overview

- **PostgreSQL**
  - Accessed via a read-only role (`agent_ro`)
  - Role provisioned by `data/db/init.sql`

- **Schema-aware SQL security**
  - Implemented using `sqlglot`
  - Includes:
    - Sensitive table detection (e.g., `users`, `api_keys`)
    - Column-level sensitivity (e.g., `users.email`, `api_keys.api_key`)
    - Detection of bulk or unbounded queries

- **Mocked email sender**
  - Emails are logged locally for inspection
  - No external email delivery occurs

- **Restricted file access**
  - File reads are limited to the `data/docs` directory

---

## Audit Logging

- All runtime decisions are logged, including:
  - Proposed action and arguments
  - Policy decision (**ALLOW / ASK / BLOCK**)
  - Triggered rule and risk reason
  - Timestamp and execution metadata

- Audit logs support:
  - Post-hoc analysis
  - Debugging and inspection
  - Accountability and traceability

---

## Setup (Docker + PostgreSQL)

### Prerequisites

- Docker
- Python 3.x

### Start PostgreSQL
```bash
docker compose up -d
