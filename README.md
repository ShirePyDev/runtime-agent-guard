# runtime-agent-guard
## Deterministic Runtime Policy Enforcement for Tool-Using LLM Agents
## Overview

**Runtime Agent Guard** is a policy-driven security layer for tool-using LLM agents.
It intercepts every tool invocation at execution time and enforces explicit security invariants before the action is executed.

Unlike prompt-level filtering or static moderation, this system operates at runtime with:

- Tool-aware inspection (SQL, email, file, web)

- Multi-step session state reasoning

- Classified data flow tracking

- Deterministic ALLOW / ASK / BLOCK decisions

- Configurable policy modes (Balanced / Strict)

- Quantified friction vs. security trade-offs

The system is designed for enterprise-grade agent deployments where LLMs interact with databases, filesystems, APIs, and communication channels.

---

## Problem Statement

- new attack surfaces:

- SQL bulk extraction

- Sensitive table access

- Credential leakage

- Cross-step data exfiltration

- Prompt-injection-induced tool misuse

- Web → database → email multi-step chains

Existing defenses focus on:

- Input moderation

- Static prompt filtering

- Model-based classification

- These approaches lack:

- Deterministic runtime enforcement

- Tool-specific reasoning

- Session-level invariants

- Formal friction measurement

Runtime Agent Guard addresses these gaps.

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

## Core Design Principles

**1. Runtime Interception**

All tool calls pass through a monitor before execution:
- **Agent → Monitor → Decision → Tool (if allowed)**
No tool executes without a policy verdict.


**2. Deterministic Policy Engine**

- Each tool call produces a structured RiskSignals object:

- Referenced tables

- Referenced columns

- Missing LIMIT indicators

- Bulk extraction signals

- Taint flags

- Tool and operation priors

- Signals are aggregated into a bounded risk score ∈ [0,1].

Decision semantics:

**| Decision | Meaning                     |**
| -------- | --------------------------- |
| ALLOW    | Safe to execute             |
| ASK      | Requires human confirmation |
| BLOCK    | High-risk action rejected   |


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
