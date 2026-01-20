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

### 1️⃣ Clone the repository
```bash
git clone https://github.com/ShirePyDev/runtime-agent-guard.git
cd runtime-agent-guard
