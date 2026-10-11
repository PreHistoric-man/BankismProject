# Bankism: Defensive AI Security Firewall for Banking Applications

Bankism is an application security firewall architecture engineered to intercept, inspect, and govern untrusted natural-language prompts in LLM-assisted banking workflows before they reach privileged financial operations.

> **CRITICAL SECURITY NOTICE**: Bankism is a defensive security prototype using fictional accounts and simulated banking models. Real financial institutions, core banking integrations, payment gateways, and automated transaction executions are strictly excluded in Phase 1.

Please see [`bankism/README.md`](./bankism/README.md) for full backend documentation, testing, and architecture specifications.

## Quick Start (Backend)

```bash
cd bankism/backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Running Backend Tests

```bash
python3 -m pytest bankism/backend/tests -v
```
