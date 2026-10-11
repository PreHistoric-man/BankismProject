# BANKISM — ENVIRONMENT CONFIGURATION & RUNTIME SETUP GUIDE

This document catalogs every environment variable referenced in the Bankism architecture, their purpose, data types, development defaults, security impacts, and secret handling requirements.

---

## 1. Environment Variable Catalog (`BANKISM_*`)

Bankism uses documented application defaults across all parameters so the platform runs immediately in development without manual variable configuration.

### 1.1 Numeric Thresholds & Windows (Documented Development Defaults)

| Variable Name | Type | Development Default | Purpose & Security Impact |
| :--- | :--- | :--- | :--- |
| `BANKISM_MIN_HISTORY_TRANSACTIONS` | Integer | `3` | Minimum completed transactions required before an account transitions from `INSUFFICIENT_HISTORY` to `ESTABLISHED`. Setting this too low creates false baseline confidence; setting it too high forces persistent cold-start handling. |
| `BANKISM_BEHAVIORAL_WINDOW_DAYS` | Integer | `30` | Rolling lookback window in days used to compute historical mean, median, standard deviation, and known counterparties. |
| `BANKISM_BEHAVIORAL_RISK_MEDIUM_THRESHOLD` | Float | `25.0` | Behavioral score boundary for `MEDIUM` risk / `STEP_UP_REVIEW`. Scores $\ge 25.0$ flag the request for additional verification. |
| `BANKISM_BEHAVIORAL_RISK_HIGH_THRESHOLD` | Float | `50.0` | Behavioral score boundary for `HIGH` risk / `REQUIRE_DUAL_APPROVAL`. Transfers $\ge 50.0$ are escalated to mandatory secondary approver sign-off. |
| `BANKISM_BEHAVIORAL_RISK_CRITICAL_THRESHOLD` | Float | `75.0` | Behavioral score boundary for `CRITICAL` risk / `HOLD_FOR_TRUSTED_REVIEW`. Transfers $\ge 75.0$ are held pending Risk Officer decision. |
| `BANKISM_AMOUNT_SPIKE_Z_SCORE_THRESHOLD` | Float | `2.5` | Statistical standard deviation threshold for flagging anomalous transaction amounts. |
| `BANKISM_AMOUNT_SPIKE_RATIO_THRESHOLD` | Float | `3.0` | Ratio of requested transfer amount relative to historical mean/median that triggers `AMOUNT_SPIKE_ANOMALY`. |
| `BANKISM_VELOCITY_HOURLY_BURST_THRESHOLD` | Integer | `3` | Maximum allowable outgoing transfers within a 1-hour window before triggering `RAPID_VELOCITY_BURST_1H`. |
| `BANKISM_VELOCITY_DAILY_BURST_THRESHOLD` | Integer | `8` | Maximum allowable outgoing transfers within a 24-hour window before triggering velocity escalation. |
| `BANKISM_REPEATED_FAILED_ATTEMPTS_THRESHOLD` | Integer | `3` | Number of rejected or firewall-blocked attempts within 24 hours that triggers `REPEATED_FAILED_OR_BLOCKED_ATTEMPTS`. |
| `BANKISM_RISK_BLOCK_THRESHOLD` | Float | `0.70` | Phase 1 AI Firewall composite risk threshold (0.0–1.0) triggering deterministic `BLOCK`. |
| `BANKISM_RISK_REVIEW_THRESHOLD` | Float | `0.35` | Phase 1 AI Firewall composite risk threshold (0.0–1.0) triggering supervisory `REVIEW`. |
| `BANKISM_HIGH_AMOUNT_THRESHOLD` | Float | `10000.00` | Static transfer amount limit (USD) triggering Step-Up MFA and dual approval. |
| `BANKISM_HIGH_RISK_DUAL_APPROVAL_THRESHOLD` | Float | `10000.00` | Static transfer amount threshold (USD) requiring secondary approver sign-off. |
| `BANKISM_TICKET_EXPIRY_SECONDS` | Integer | `300` | Validity window of signed cryptographic `AuthorizationTicket` in seconds (5 minutes). |
| `BANKISM_DUAL_APPROVAL_EXPIRY_SECONDS` | Integer | `3600` | TTL of pending dual-approval requests in seconds (1 hour). |
| `BANKISM_RISK_ASSESSMENT_RETENTION_DAYS` | Integer | `90` | Retention window (days) for persisted behavioral risk assessments. |

---

### 1.2 Feature Flags & Security Guardrails

| Variable Name | Type | Development Default | Purpose & Security Impact |
| :--- | :--- | :--- | :--- |
| `BANKISM_ALLOW_TRANSACTION_EXECUTION` | Boolean | `false` | Phase 1 firewall safety invariant. Even if set to `true`, the firewall inspect endpoint enforces `execution_permitted = false` in code. |
| `BANKISM_ENABLE_HEURISTIC_DETECTION` | Boolean | `true` | Enables zero-width space, Unicode obfuscation, and character entropy heuristics. |
| `BANKISM_ENABLE_PAYMENT_METADATA_CHECKS` | Boolean | `true` | Scans payment memos, recipient IDs, and actions for SQLi, XSS, and command injection patterns. |
| `BANKISM_MASK_LOG_SENSITIVE_DATA` | Boolean | `true` | Enforces PCI-DSS and GLBA redacting of PANs, SSNs, and Bearer tokens before logging or auditing. |
| `BANKISM_HIGH_BEHAVIORAL_RISK_REQUIRES_DUAL_APPROVAL` | Boolean | `true` | Automatically escalates `HIGH` and `CRITICAL` behavioral risk transfers to `PENDING_DUAL_APPROVAL`. |
| `BANKISM_ENABLE_TOCTOU_WATERMARK_CHECK` | Boolean | `true` | Validates that the account's historical watermark has not drifted between authorization and execution. |

---

### 1.3 Cryptographic Secrets Handling

| Variable Name | Type | Secret? | Development Handling & Production Requirement |
| :--- | :--- | :--- | :--- |
| `BANKISM_HMAC_SECRET` | String | **Yes** | Used solely by the local sandbox to sign and verify `AuthorizationTicket` tokens using HMAC-SHA256. In development, an isolated fallback (`bankism-dev-hmac-secret-key-32bytes-min-isolated`) is used. In production, provide a cryptographically secure random 256-bit string (`openssl rand -hex 32`). Empty or `< 16`-byte keys cause immediate fail-closed termination. |

> **Note on External APIs:** Bankism contains **no external LLM or core banking API dependencies**. It operates as a local, fully deterministic, simulated defense platform. No third-party API keys (OpenAI, Anthropic, Stripe, Plaid) are required or used.

---

## 2. Startup & Development Instructions

### Running the Web Application
```bash
# Install dependencies
npm install

# Start Vite development server on port 3000
npm run dev
```

The application will bind to `0.0.0.0:3000` and can be accessed in any modern browser.

### Verifying Compilation & Linting
```bash
# Type check TypeScript codebase
npm run lint

# Production build verification
npm run build
```
