# Bankism: Defensive AI Security Firewall & Secure Simulated Transaction Sandbox

Bankism is an application security firewall architecture and secure transaction simulation sandbox engineered to intercept, inspect, and govern untrusted natural-language prompts in LLM-assisted banking workflows before they reach privileged financial operations.

> **CRITICAL SECURITY NOTICE**: Bankism is a defensive research prototype using fictional accounts and simulated banking models. Real financial institutions, core banking integrations, payment gateways, and external money-transfer services are strictly excluded.

---

## Architecture Overview

Bankism operates across two defensive tiers:
1. **Defensive AI Security Firewall (Phase 1 & 1.5)**: Intercepts natural-language prompts, sanitizes input (NFKC Unicode, zero-width characters), masks PCI-DSS/GLBA sensitive data, classifies adversarial vectors (prompt injections, jailbreaks, malicious payment metadata, obfuscation), and enforces deterministic policy rules with fail-closed safety.
2. **Secure Simulated Transaction Sandbox (Phase 2)**: An isolated, server-side verified execution environment featuring:
   - **Trusted Identity Boundary**: Principals are derived exclusively from verified server-side authentication headers (`X-Bankism-Mock-User` or Bearer token); client-provided user IDs in payloads are strictly untrusted.
   - **Account Access Authorization**: Strict ownership boundary prevents cross-user account access, reads, and transfers.
   - **Persistent SQLite Ledger**: Exact integer minor units (cents) prevent floating-point arithmetic drift. Atomic debit/credit updates with sufficiency checks prevent race conditions and overspending.
   - **Deterministic Authorization**: An AI verdict of `APPROVE` is never sufficient alone to authorize a transfer. A server-signed cryptographic `AuthorizationTicket` (HMAC-SHA256) is issued only when all deterministic checks pass.
   - **Single Protected Execution Gateway**: The executor requires a valid, unconsumed, unexpired ticket. Replay attacks and parameter tampering fail closed.
   - **Dual Approval for High-Risk Transfers**: Transactions exceeding threshold ($\ge \$10,000$) require a second distinct authenticated approver.
   - **Tamper-Evident Audit Trail**: Persistent audit events are chained via cryptographic SHA-256 hashes (`event_hash = SHA256(prev_hash || ...)`).

---

## Directory Structure

```text
bankism/
  backend/
    app/
      __init__.py
      main.py                  # FastAPI application entrypoint & lifespan
      config.py                # Pydantic Settings with BANKISM_ prefix
      api/
        __init__.py
        routes.py              # Firewall, accounts, transfers, approvals, and audit endpoints
      schemas/
        __init__.py
        auth.py                # AuthenticatedPrincipal & UserRole schemas
        common.py              # Verdict, RiskLevel, ThreatCategory enums
        firewall.py            # Inspection request & response models
        banking.py             # Transfer prepare/confirm/approve & balance schemas
      security/
        __init__.py
        auth.py                # Server-side principal derivation & ownership authorization
        masking.py             # PCI-DSS & GLBA sensitive data masking & redaction
        sanitization.py        # Unicode NFKC canonicalization & zero-width stripper
      classification/
        __init__.py
        patterns.py            # Regex signatures for adversarial vectors
        detector.py            # Threat detector & composite risk scoring engine
      policies/
        __init__.py
        rules.py               # Deterministic security rules (POL-001 through POL-007)
        engine.py              # Fail-closed policy evaluation engine
      ledger/
        __init__.py
        db.py                  # SQLite connection manager & idempotent migrations
        models.py              # Minor-unit cents conversion & ledger models
        operations.py          # Atomic debit/credit, balance, and idempotency logic
      authorization/
        __init__.py
        tickets.py             # Canonical transaction hash & HMAC-SHA256 signing
        service.py             # Deterministic authorization checks & ticket issuer
        dual_approval.py       # High-risk dual approval manager
      executor/
        __init__.py
        executor.py            # Single protected execution gateway & replay prevention
      audit/
        __init__.py
        logger.py              # Masking log handler & CRLF log injection neutralizer
        recorder.py            # In-memory inspection telemetry
        tamper_evident.py      # SQLite hash-chained tamper-evident audit store
    tests/
      __init__.py
      conftest.py              # Pytest fixtures & isolated DB setup
      test_phase2_audit_regression.py # Phase 2.1–2.7 Red-Team regression suite (12 tests)
      test_phase2_sandbox.py   # Phase 2 Sandbox security invariant suite (16 tests)
      test_security_invariants.py # Phase 1.5 Security regression suite (11 tests)
      test_firewall_inspect.py # End-to-end firewall inspect tests (11 tests)
      test_health.py           # Subsystem health tests (2 tests)
      test_detector.py         # Threat classification tests (4 tests)
      test_policy_engine.py    # Policy rules & fail-closed tests (3 tests)
      test_masking.py          # Sensitive data redaction tests (5 tests)
      test_sanitization.py     # Unicode & anti-obfuscation tests (3 tests)
      test_schemas.py          # Pydantic schema validation tests (4 tests)
      test_banking_simulation.py # Simulated banking isolation tests (2 tests)
    requirements.txt           # Pinned production and test dependencies
    .env.example               # Environment variable templates
    .gitignore
  frontend/
    README.md
  README.md
```

---

## Authentication & Fictional Users

Bankism derives authentication from the `X-Bankism-Mock-User` header or a `Bearer` token.

| Username | User ID | Role | Authorized Accounts | Can Dual-Approve |
|---|---|---|---|---|
| `alice` | `USR-4401-ALICE` | `CUSTOMER` | `ACC-1001-CHK`, `ACC-2002-SAV` | No |
| `bob` | `USR-8899-BOB` | `CUSTOMER` | `ACC-3003-BUS` | No |
| `charlie` | `USR-9900-CHARLIE` | `APPROVER` | None (Risk Officer) | **Yes** |
| `dave` | `USR-1100-DAVE` | `CUSTOMER` | `ACC-4004-CHK` | No |

---

## API Endpoints

### 1. Banking Ledger & Accounts
- `GET /banking/accounts`: List accounts owned by the authenticated caller.
- `GET /banking/accounts/{account_id}/balance`: Get balance of an authorized account.
- `GET /banking/accounts/{account_id}/transactions`: Get transaction history of an authorized account (bounded).

### 2. Transfers & Authorization
- `POST /banking/transfers/prepare`: Validate transfer parameters, check funds, run AI firewall, and issue an unforgeable `AuthorizationTicket` (or pending dual-approval request if amount $\ge \$10,000$).
- `POST /banking/transfers/confirm`: Submit signed `AuthorizationTicket` to the protected executor to execute the transfer.
- `POST /banking/transfers/approve`: Secondary approver signs off on a pending high-risk transaction.

### 3. Security & Audit
- `GET /health`: Health check and status of all subsystems.
- `POST /firewall/inspect`: Inspect untrusted prompts for threat detection and policy evaluation.
- `GET /banking/audit/verify`: Verify the cryptographic integrity of the SHA-256 audit hash chain.

---

## Running Backend Tests

Execute the full suite with Pytest:

```bash
python3 -m pytest bankism/backend/tests -v
```

**Actual Results**: 73 passed in ~1.71s (Zero failures).

---

## Demonstration Workflows

### Scenario A: Successful Standard Transfer ($250.00)
1. **Prepare Transfer**:
   ```bash
   curl -X POST http://localhost:8000/banking/transfers/prepare \
     -H "X-Bankism-Mock-User: alice" \
     -H "Content-Type: application/json" \
     -d '{
       "source_account_id": "ACC-1001-CHK",
       "destination_account_id": "ACC-2002-SAV",
       "amount": 250.00,
       "memo": "Transfer to savings"
     }'
   ```
   *Result*: HTTP 200 with signed `AuthorizationTicket` (HMAC-SHA256).

2. **Confirm & Execute**:
   ```bash
   curl -X POST http://localhost:8000/banking/transfers/confirm \
     -H "X-Bankism-Mock-User: alice" \
     -H "Content-Type: application/json" \
     -d '{
       "ticket": <TICKET_OBJECT_FROM_STEP_1>
     }'
   ```
   *Result*: HTTP 200 with `ExecutionReceipt` and audit event hash. Ticket is atomically consumed.

### Scenario B: Rejected Cross-Account Access (HTTP 403)
```bash
curl -X GET http://localhost:8000/banking/accounts/ACC-1001-CHK/balance \
  -H "X-Bankism-Mock-User: bob"
```
*Result*: HTTP 403 Forbidden (`ACCOUNT_ACCESS_DENIED: Principal 'bob' does not own 'ACC-1001-CHK'`).

### Scenario C: High-Risk Dual Approval Workflow ($15,000.00)
1. Bob prepares a transfer of $15,000.00:
   *Result*: Returns `status: "PENDING_DUAL_APPROVAL"` with `request_id: "apr_..."`.
2. Bob attempts to approve his own transfer $\rightarrow$ Rejected (`SELF_APPROVAL_PROHIBITED`).
3. Charlie (`X-Bankism-Mock-User: charlie`) submits approval via `/banking/transfers/approve` $\rightarrow$ Valid `AuthorizationTicket` is issued.
4. Bob executes transfer via `/banking/transfers/confirm` $\rightarrow$ Completed.
