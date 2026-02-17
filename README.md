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

- **| Decision | Meaning                     |**
- | -------- | --------------------------- |
- | ALLOW    | Safe to execute             |
- | ASK      | Requires human confirmation |
- | BLOCK    | High-risk action rejected   |

**3. Multi-Step Security Invariants**

The system maintains session state:

- classified_accessed

- classified_sources

- risk_budget

- Taint history window

Example invariant:

If classified data is accessed during the session, any subsequent egress (email) must be ASK (Balanced) or BLOCK (Strict).

This prevents multi-step data exfiltration chains.

**4. SQL Sensitivity Classification**

SQL statements are parsed using structured AST analysis (via sqlglot).

Detection includes:

- Sensitive table access

- Sensitive column access

- Column-name heuristics (email, password, token, api_key)

- Bulk access (SELECT * without LIMIT)

- Explicit LIMIT absence

Classification rules are configurable via classification.json.

**5. Taint Propagation**

Web search results and external inputs are marked as tainted.

The monitor:

- Tracks taint across steps

- Infers taint from history

- Detects tainted content usage in outgoing email

- Escalates intervention accordingly

**6. Risk Budget Enforcement**

Each session maintains a configurable risk budget.

- High-risk actions deplete the budget.

- Low remaining budget escalates ALLOW → ASK.

- Budget exhaustion forces BLOCK.

This mitigates persistent probing and incremental attack strategies.

**7. Repetition Escalation**

Repeated ASK or BLOCK attempts escalate:

- Repeated ASK → higher risk

- Repeated BLOCK → forced BLOCK

Prevents brute-force or persistence attacks.

## Policy Modes

## Balanced Mode

**Sensitive SQL → ASK**

**Classified → egress → ASK**

- Internal safe email allowed

- Designed for enterprise productivity with human oversight

## Strict Mode

- **Any classified SQL → BLOCK**

- **Classified → egress → BLOCK**

- More conservative posture

- Suitable for regulated environments

### Evaluation Framework

**The system includes a benchmark suite:**

- Multi-step attack episodes

- SQL exfiltration scenarios

- File boundary violations

- Web → email taint chains

- Credential leakage patterns

**Evaluation protocols:**

- **STOP_ON_ASK (measures friction)**
- **AUTO_APPROVE_ASK (measures downstream containment)**

**Metrics:**

- TPR / FPR (BLOCK-only)

- TPR / FPR (intervention: ASK or BLOCK)

- ASK per episode (friction)

- Latency (ms per decision)

- Policy match consistency

## **Repository Structure**

src/
  monitor.py        # Runtime guard + policy engine
  signals.py        # Risk signal aggregation
  classification.py # Sensitivity classifier
  agent.py          # Tool-using agent loop
  tools.py          # Tool implementations
  logger.py         # Structured audit logs
  sql_policy.py     # SQL parsing and risk logic

eval/
  run_eval.py
  ragsecbench_v1.jsonl
  labeling_rules.md
  schema.md
  baselines/

demo/
  demo_stepwise.py
  demo_taint_history.py

---

## Threat Model

**The system assumes:**

- The LLM may be manipulated by prompt injection.

- External data sources may be adversarial.

- Tool invocations may expose sensitive resources.

- Multi-step chains may occur across session boundaries.

The system does not attempt to:

- Prove formal non-interference.

- Replace full DLP solutions.

- Detect semantic covert channels.

It enforces runtime policy invariants at the tool boundary.

## Performance Characteristics

- Deterministic enforcement

- No secondary LLM in decision loop

- Sub-millisecond average evaluation latency

- Suitable for inline production gating


## Limitations

- Rule-based sensitivity classification

- No semantic query understanding beyond heuristics

- Risk scoring weights are manually tuned

- Limited formal guarantees


## Intended Use

**This project is intended for:**

- Research on LLM agent security

- Enterprise runtime guardrail prototypes

- Tool-aware policy enforcement experiments

- Multi-step exfiltration detection studies


## License

**MIT License**

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
