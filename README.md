# runtime-agent-guard

## Overview

**runtime-agent-guard** is a runtime security enforcement system for **tool-using AI agents**.  
It intercepts proposed tool actions and enforces explicit policy decisions — **ALLOW**, **ASK**, or **BLOCK** — *before* any tool is executed.

Instead of focusing on new language model training or prompt-level filtering, this project emphasizes:

- Runtime control of agent behavior  
- Auditable and inspectable decisions  
- Least-privilege access to external systems  
- Human-in-the-loop safety for high-risk actions  

The system is designed for research, experimentation, and demonstration of **trust-aware agent execution**.

---

## Key Features

- Runtime interception of all tool calls  
- Explicit policy decisions (**ALLOW / ASK / BLOCK**)  
- Schema-aware SQL risk analysis  
- Sensitive content detection for email actions  
- Restricted filesystem access  
- Audit logging of decisions and outcomes  
- Modular, extensible architecture  

---

## 🚀 Quick Start

This project includes a one-command demo that shows how the runtime guard behaves under different security scenarios.

## System Architecture

The system operates as a guarded agent execution loop:
-The agent proposes an action (tool name and arguments)
-A runtime monitor evaluates intent alignment and tool-specific risk
-A policy decision is enforced:
-ALLOW — the tool executes immediately
-ASK — human approval is required
-BLOCK — execution is prevented
-Tool outputs are optionally redacted and written to an audit log
This design ensures that unsafe or ambiguous actions are intercepted before any real-world side effects occur.
 
 ---

## Core Components

-src/agent.py
  -Minimal agent loop and enforcement logic
-src/monitor.py
-Runtime trust, intent, and risk monitoring
-src/sql_policy.py
-Schema-aware SQL risk analysis using sqlglot
src/policy.py
-Policy definitions, thresholds, and output redaction rules
-src/tools.py
-Tool implementations and centralized tool registry
-src/logger.py
-Runtime audit logging for decisions and actions
The codebase is intentionally modular to support experimentation and extension.


## Security Design Principles

-Runtime enforcement
-All tool calls are intercepted before execution.
-Least privilege
-External systems (e.g., databases) are accessed using restricted, read-only roles.
Defense in depth
-Independent protections exist across monitoring, tools, database access, and output handling.
-Human-in-the-loop
-High-impact or ambiguous actions require explicit approval.

---

## Tooling Overview

PostgreSQL
-Accessed via a read-only role (agent_ro) provisioned by data/db/init.sql
Schema-aware SQL security using sqlglot, including:
-Sensitive table detection (e.g., users, api_keys)
-Column-level sensitivity (e.g., users.email, api_keys.api_key)
-Detection of bulk or unbounded queries
Mocked email sender
-Emails are logged locally for inspection; no external delivery occurs
Restricted file access
-File reads are limited to the data/docs directory

---

## Audit Logging

All decisions and relevant execution metadata are written to runtime logs, including:
-Proposed action and arguments
-Policy decision (ALLOW / ASK / BLOCK)
-Risk reason and rule triggered
-Timestamp and execution metadata
This supports post-hoc analysis and accountability.

---

## Setup (Docker + PostgreSQL)
Prerequisites
-Docker
-Python 3.x

**Start PostgreSQL**
*docker compose up -d*

---

### 1️⃣ Clone the repository
```bash
git clone https://github.com/ShirePyDev/runtime-agent-guard.git
cd runtime-agent-guard
