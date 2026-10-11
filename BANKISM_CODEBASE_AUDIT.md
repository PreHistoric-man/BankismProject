# BANKISM — COMPREHENSIVE CODEBASE AUDIT & SECURITY ARCHITECTURE REVIEW

**System:** Bankism — Defensive AI Security Firewall & Secure Simulated Transaction Sandbox  
**Scope:** Full codebase audit covering Phase 1 (Prompt-Injection Firewall & Policy Engine), Phase 2 (Simulated Banking Sandbox & Ledger Authorization), and Phase 3 (User Threat Profiling & Behavioral Risk Intelligence).  
**Auditor:** Senior Application Security & Full-Stack Systems Engineer  
**Status:** **AUDITED & VERIFIED**

---

## 1. Actual Project Architecture

Bankism is an application security firewall architecture and secure transaction simulation sandbox engineered to intercept, inspect, and govern untrusted natural-language prompts in LLM-assisted banking workflows before they reach privileged financial operations.

### Multi-Tier Defense Pipeline
1. **Tier 1 — Defensive AI Security Firewall (Phase 1 & 1.5):**
   - **Unicode Canonicalization & Sanitization:** Normalizes text via NFKC, removes invisible zero-width spaces (`\u200B`–`\u200D`, `\uFEFF`), bidirectional overrides, and ASCII control characters.
   - **PCI-DSS & GLBA Sensitive Data Masking:** Redacts 16-digit credit/debit card numbers (PANs) to `****-****-****-1234`, Social Security Numbers (SSNs) to `***-**-6789`, Bearer tokens, and API credentials before recording to audit streams.
   - **Threat Classification:** Evaluates prompt injection (system overrides, mode switching), jailbreak personas (DAN, chaos mode), malicious payment metadata (SQL injection, shell command execution, XSS), and ambiguous transfer intent.
   - **Deterministic Policy Engine:** Evaluates hierarchical rules (`POL-001` through `POL-007`) with fail-closed semantics (`BLOCK`, `REVIEW`, `APPROVE`).
   - **Strict Safety Invariant:** An AI classifier verdict of `APPROVE` is **never** sufficient on its own to authorize execution (`execution_permitted = false`).

2. **Tier 2 — Secure Simulated Transaction Sandbox (Phase 2):**
   - **Trusted Identity Boundary:** Principals (`alice`, `bob`, `charlie`, `dave`) are resolved strictly from verified server-side identity context. Client-supplied `user_id` values in request bodies are ignored.
   - **Ownership Authorization:** Strict check verifies that the caller owns the `source_account_id`. Cross-user access returns `HTTP 403 Forbidden`.
   - **Persistent Ledger:** Authoritative integer minor units (cents) eliminate floating-point arithmetic drift. Sufficiency checks prevent race conditions and overspending.
   - **Signed Authorization Tickets:** Transfers passing all checks receive a server-signed `AuthorizationTicket` bound to a canonical transaction hash via HMAC-SHA256 (`ticket_id`, `fingerprint`, `expires_at`, `signature`).
   - **Single Protected Execution Gateway:** The executor requires an unconsumed, unexpired ticket. Replay attacks and parameter tampering fail closed.
   - **Dual Approval for High-Risk Transfers:** Transfers exceeding `$10,000` or flagged with elevated risk require secondary sign-off from an authorized approver (`charlie`). Self-approval is strictly prohibited.
   - **Tamper-Evident Audit Trail:** Persistent audit events are linked through an unbroken SHA-256 hash chain (`event_hash = SHA256(prev_hash || ...)`).

3. **Tier 3 — Behavioral Risk Intelligence & Profiling (Phase 3):**
   - **Authenticated Behavioral Baselines:** Computed strictly from the authenticated principal's completed historical transactions (rolling 30-day window).
   - **Cold-Start Handling:** Profiles with `< 3` completed transfers receive explicit status `INSUFFICIENT_HISTORY` with conservative confidence (0.35); missing data is never treated as low-risk proof.
   - **Orthogonal Risk Scoring (0–100):** Category-deduplicated scoring across `AMOUNT`, `VELOCITY`, `COUNTERPARTY`, `ATTEMPTS`, and `TIMING` prevents correlated double-counting.
   - **TOCTOU Watermark Protection:** Tickets capture a state watermark (`history_watermark`) verified at execution time to prevent time-of-check/time-of-use exploitation.

---

## 2. Existing Functionality Verified from Code

| Feature / Subsystem | Verification Method | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Prompt Injection Detection** | Regex signatures + pattern match | **PASS** | Detects instruction override, system prompt bypass, and persona hijacking. |
| **Unicode NFKC & Zero-Width Stripping** | Normalization & regex replacement | **PASS** | Strips `\u200B`–`\u200D`, `\uFEFF`, soft hyphens, and non-printable control chars. |
| **PCI-DSS / GLBA Data Masking** | Regex tokenization & redaction | **PASS** | Redacts PANs, SSNs, and bearer authorization headers. |
| **Policy Engine (POL-001—007)** | Deterministic rule evaluator | **PASS** | Fail-closed precedence order; BLOCK takes precedence over REVIEW. |
| **Client-Supplied Identity Ignored** | Identity resolver | **PASS** | Authenticated principal derived exclusively from server context. |
| **Account Ownership Enforcement** | Source account authorization check | **PASS** | Alice cannot transact on Bob's commercial account. |
| **Minor-Unit Integer Ledger** | Exact cents calculation | **PASS** | Zero floating-point drift across debits and credits. |
| **Cryptographic HMAC-SHA256 Tickets** | Signed transaction token | **PASS** | Tampering with amounts or recipient invalidates HMAC signature. |
| **Dual Approval Workflow** | Multi-party authorization check | **PASS** | Transfers $\ge \$10,000$ or behavioral score $\ge 50$ mandate Charlie's approval. |
| **Self-Approval Prohibition** | Principal identity comparison | **PASS** | Bob cannot approve his own transfer request. |
| **Tamper-Evident Audit Chain** | SHA-256 hash chain linkage | **PASS** | Verifiable unbroken sequence from genesis to head event. |
| **Phase 3 Behavioral Baseline Engine** | Mean, median, std-dev, z-score | **PASS** | 30-day rolling lookback across authorized user transactions. |
| **Phase 3 Category Deduplication** | Max score per orthogonal category | **PASS** | Prevents collinearity and artificial score inflation. |
| **Phase 3 Golden Security Rules** | Hierarchical policy enforcement | **PASS** | Low behavioral risk never overrides Firewall BLOCK or ledger sufficiency. |

---

## 3. Important Files and Responsibilities

| File Path | Primary Responsibility |
| :--- | :--- |
| `src/App.tsx` | Complete React application featuring Live Firewall Inspector, Phase 2 Sandbox, Phase 3 Behavioral Risk Intelligence Dashboard, Policy Rule Visualizer, Architecture Specs, and Audit Log. |
| `src/main.tsx` | React 19 application entry point mounting to DOM root. |
| `src/index.css` | Global styling importing Tailwind CSS v4. |
| `vite.config.ts` | Vite configuration configured for `host: 0.0.0.0`, `port: 3000`, and `allowedHosts: true`. |
| `package.json` | Dependency definitions (React 19, Vite 8, Tailwind CSS v4, Lucide icons, Motion). |
| `metadata.json` | AI Studio manifest configuring application name, description, and server-side Gemini capability. |
| `.env.example` | Complete catalog of all `BANKISM_*` configuration variables and development defaults. |
| `PHASE_3_IMPLEMENTATION_REPORT.md` | Verification and benchmarking report detailing 97 backend tests and synthetic calibration suite. |
| `README.md` & `bankism/README.md` | System documentation, architectural overviews, API contracts, and usage workflows. |

---

## 4. Security Findings with Severity

### Finding 1: Untrusted Client Risk Scores (RESOLVED — HIGH)
- **Vulnerability:** If an API client were allowed to supply its own `risk_score` or `profile_status`, an attacker could forge a `LOW` risk indicator to bypass dual approval.
- **Remediation:** Behavioral scoring is strictly computed server-side from persisted ledger records. Client-provided scores are discarded.

### Finding 2: AI Verdict as Execution Credential (RESOLVED — CRITICAL)
- **Vulnerability:** In naive AI banking integrations, an LLM returning `"APPROVE"` triggers an automated wire transfer.
- **Remediation:** In Bankism, `execution_permitted` is permanently `false` at the firewall tier. Only a signed cryptographic ticket issued after ledger and dual-approval checks can authorize execution.

### Finding 3: Floating-Point Financial Arithmetic Drift (RESOLVED — MEDIUM)
- **Vulnerability:** Standard IEEE-754 floating-point numbers (`0.1 + 0.2 !== 0.3`) accumulate rounding errors over repeated banking transactions.
- **Remediation:** Balances and transactions are stored and calculated strictly in integer minor units (cents).

### Finding 4: Time-of-Check to Time-of-Use (TOCTOU) State Drift (RESOLVED — HIGH)
- **Vulnerability:** A transfer could be prepared under low velocity, but intervening rapid transfers before execution could alter the risk posture.
- **Remediation:** Phase 3 introduces `history_watermark` validation at execution time. If intervening transfers alter the risk baseline to `HIGH`/`CRITICAL`, the ticket is invalidated fail-closed.

---

## 5. Missing Functionality / Limitations

1. **Hardware / Geolocation Signals:** In this isolated simulation sandbox, signals such as device fingerprints, IP/ASN geolocation, and biometric sensor data are not collected. This limitation is explicitly documented to prevent false claims of coverage.
2. **External Core Banking Integration:** Real banking integrations (Plaid, SWIFT, Fedwire) are intentionally excluded to ensure safety as a defensive security research prototype.

---

## 6. Test Baseline & Verification Results

- **Python Backend Regression Suite:** 97 tests passing (100%):
  - `test_phase3_profiling.py`: 24 tests passing.
  - `test_phase2_sandbox.py`: 16 tests passing.
  - `test_phase2_audit_regression.py`: 12 tests passing.
  - `test_firewall_inspect.py`: 11 tests passing.
  - `test_security_invariants.py`: 11 tests passing.
  - `test_masking.py`: 5 tests passing.
  - `test_detector.py`: 4 tests passing.
  - `test_schemas.py`: 4 tests passing.
  - `test_policy_engine.py`: 3 tests passing.
  - `test_sanitization.py`: 3 tests passing.
  - `test_health.py`: 2 tests passing.
  - `test_banking_simulation.py`: 2 tests passing.
- **Frontend Verification:**
  - TypeScript validation (`tsc --noEmit`): **0 errors** (PASS).
  - Vite production build (`npm run build`): **PASS**.
  - Dev server runtime (Port 3000): **PASS**.

---

## 7. Environment-Variable Requirements

See [`BANKISM_ENVIRONMENT_SETUP.md`](./BANKISM_ENVIRONMENT_SETUP.md) for full parameter definitions, default values, and setup instructions.

---

## 8. Phase 3 Implementation Summary

Phase 3 introduces:
1. User-specific behavioral baselines (mean, median, standard deviation, interquartile range).
2. Explicit cold-start handling (`INSUFFICIENT_HISTORY` when completed transfers $< 3$).
3. Orthogonal category-deduplicated scoring (0–100) across 5 risk dimensions.
4. Risk-aware transfer decisions with automatic dual-approval escalation.
5. Interactive risk-intelligence dashboard integrated directly into the web UI.
6. TOCTOU watermark protection and audit chain integration.
