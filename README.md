# runtime-agent-guard

## Overview

**runtime-agent-guard** is a runtime security enforcement system for **tool-using AI agents**.
It intercepts proposed tool actions and enforces explicit policy decisions **before any tool execution occurs**.

The system produces one of three decisions for every agent action:

- **ALLOW** — action is safe and executed immediately
- **ASK** — action requires explicit human approval
- **BLOCK** — action is unsafe and execution is prevented

The project focuses on:
- Runtime control of agent behavior
- Auditable and inspectable decisions
- Least-privilege access to external systems
- Human-in-the-loop safety for high-risk actions

Designed for **research, experimentation, and demonstration** of trust-aware agent execution.

---

## Key Features

- Runtime interception of all agent tool calls
- Explicit policy decisions (**ALLOW / ASK / BLOCK**)
- Schema-aware SQL risk analysis
- Sensitive content detection for email actions
- Restricted filesystem access
- Centralized audit logging
- Modular and extensible architecture

---

## System Architecture

The system is implemented as a **guarded agent execution loop**.
All agent actions are intercepted by a runtime guard that operates independently from the underlying language model.

### Execution Flow

1. **Agent Proposal**
   - The agent proposes an action consisting of:
     - Tool name
     - Tool arguments

2. **Runtime Monitoring**
   - A runtime monitor evaluates:
     - Intent alignment
     - Tool-specific risk
     - Policy constraints

3. **Policy Decision**
   - One of three decisions is produced:
     - **ALLOW**
     - **ASK**
     - **BLOCK**

4. **Execution and Logging**
   - Allowed actions execute under restricted permissions
   - Tool outputs may be redacted
   - All decisions and metadata are written to audit logs

This design ensures unsafe or ambiguous actions are stopped **before real-world side effects occur**.

---

## Core Components

- `src/agent.py`  
  Minimal agent loop that enforces runtime guard decisions

- `src/monitor.py`  
  Runtime trust, intent, and risk monitoring

- `src/sql_policy.py`  
  Schema-aware SQL risk analysis using `sqlglot`

- `src/policy.py`  
  Central policy definitions and decision thresholds

- `src/tools.py`  
  Tool implementations and registry

- `src/logger.py`  
  Runtime audit logging for decisions and metadata

The codebase is intentionally modular to support experimentation and extension.

---

## Security Design Principles

- **Runtime enforcement**  
  All tool calls are intercepted before execution

- **Least privilege**  
  External systems are accessed using restricted, read-only roles

- **Defense in depth**  
  Independent protections across monitoring, policy, and tool layers

- **Human-in-the-loop**  
  High-impact or ambiguous actions require explicit approval

---

## Tooling Overview

- **PostgreSQL**
  - Accessed via a read-only role (`agent_ro`)
  - Role provisioned by `data/db/init_sqlite.sql`

- **Schema-aware SQL security**
  - Sensitive table and column detection
  - Bulk or unbounded query detection

- **Mocked email sender**
  - Emails are logged locally
  - No external delivery occurs

- **Restricted file access**
  - File reads limited to `data/docs`

---

## Audit Logging

All runtime decisions are logged, including:
- Proposed action and arguments
- Policy decision (**ALLOW / ASK / BLOCK**)
- Triggered rule and risk reason
- Timestamp and execution metadata

Logs support debugging, inspection, and accountability.

---

### Limitations

- Does not aim to block all prompt-level attacks

- Policies are rule-based rather than learned

- Human approval is simulated rather than fully interactive

---

## Quick Start (Docker + PostgreSQL)

### Prerequisites
- Docker
- Python 3.x

### Start services
```bash
git clone https://github.com/ShirePyDev/runtime-agent-guard.git
cd runtime-agent-guard
docker compose up -d
