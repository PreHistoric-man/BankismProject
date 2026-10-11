# BANKISM PHASE 3 — IMPLEMENTATION & SECURITY VERIFICATION REPORT

**Project:** Bankism — Defensive AI Security Firewall & Behavioral Risk Intelligence  
**Phase:** Phase 3 — User Threat Profiling & Behavioral Risk Intelligence (`phase3-v1.0.0`)  
**Verification Status:** **97 / 97 Backend Pytest Tests Passing (100%)** · **Frontend TypeScript & Vite Production Build Verified**

---

## 1. Executive Summary

Phase 3 extends Bankism's verified Phase 1 (AI Prompt-Injection Firewall & Deterministic Policy Engine) and Phase 2 (Simulated Banking Sandbox, SQLite Ledger, HMAC-SHA256 Signed Authorization Tickets, Dual Approval, and Tamper-Evident Audit Chain) with **User Threat Profiling & Behavioral Risk Intelligence**.

The behavioral risk system evaluates whether a proposed transfer deviates materially from the authenticated principal's observed transaction baseline. It operates as an **additive, deterministic-first, explainable layer** that can escalate required controls (`STEP_UP_REVIEW`, `REQUIRE_DUAL_APPROVAL`, `HOLD_FOR_TRUSTED_REVIEW`) without ever weakening or overriding Phase 1/2 security controls.

### Verified End-to-End Security Pipeline
```text
User Request
  → Identity Verification (Principal & Account Ownership Check)
  → AI Security Firewall (Prompt Injection, Jailbreak, Metadata SQLi/XSS/Cmd, Obfuscation)
  → Behavioral Risk Assessment (Baseline Features, Category-Deduplicated Scoring, Cold-Start Handling)
  → Deterministic Authorization (Limits, Balance, Risk Escalation, Dual Approval Gate)
  → Protected Executor (HMAC Ticket Verification, Replay Check, TOCTOU Watermark Verification)
  → Atomic SQLite Ledger + Tamper-Evident SHA-256 Audit Chain
```

---

## 2. Environment Variable Audit (`BANKISM_*`)

All `BANKISM_*` environment variables have been audited and categorized in `.env.example` and `bankism/backend/app/config.py`. Because Bankism is a local/simulated banking security demonstration with zero external banking or LLM API calls, **no external API keys or third-party secrets exist or are required**.

### 2.1 Numeric Thresholds (Documented Development Defaults)
| Environment Variable | Default | Purpose |
| :--- | :--- | :--- |
| `BANKISM_RISK_BLOCK_THRESHOLD` | `0.70` | Phase 1 AI Firewall composite risk threshold (0.0–1.0) triggering deterministic `BLOCK`. |
| `BANKISM_RISK_REVIEW_THRESHOLD` | `0.35` | Phase 1 AI Firewall composite risk threshold (0.0–1.0) triggering supervisory `REVIEW`. |
| `BANKISM_HIGH_AMOUNT_THRESHOLD` | `10000.00` | Phase 1 static transfer amount threshold (USD) requiring step-up MFA and supervisory review. |
| `BANKISM_HIGH_RISK_DUAL_APPROVAL_THRESHOLD` | `10000.00` | Phase 2 static transfer amount threshold (USD) requiring secondary approver sign-off. |
| `BANKISM_TICKET_EXPIRY_SECONDS` | `300` | Phase 2 cryptographic `AuthorizationTicket` validity window in seconds (5 minutes). |
| `BANKISM_DUAL_APPROVAL_EXPIRY_SECONDS` | `3600` | Phase 2 pending dual-approval request TTL in seconds (1 hour). |
| `BANKISM_MIN_HISTORY_TRANSACTIONS` | `3` | Phase 3 minimum completed transfers required before a profile transitions from `INSUFFICIENT_HISTORY` to `ESTABLISHED`. |
| `BANKISM_BEHAVIORAL_WINDOW_DAYS` | `30` | Phase 3 rolling lookback window (days) for baseline feature extraction. |
| `BANKISM_BEHAVIORAL_RISK_MEDIUM_THRESHOLD` | `25.0` | Phase 3 behavioral risk score threshold (0–100) for `MEDIUM` risk / `STEP_UP_REVIEW`. |
| `BANKISM_BEHAVIORAL_RISK_HIGH_THRESHOLD` | `50.0` | Phase 3 behavioral risk score threshold (0–100) for `HIGH` risk / `REQUIRE_DUAL_APPROVAL`. |
| `BANKISM_BEHAVIORAL_RISK_CRITICAL_THRESHOLD` | `75.0` | Phase 3 behavioral risk score threshold (0–100) for `CRITICAL` risk / `HOLD_FOR_TRUSTED_REVIEW`. |
| `BANKISM_AMOUNT_SPIKE_Z_SCORE_THRESHOLD` | `2.5` | Phase 3 z-score threshold for flagging statistical transfer amount spikes. |
| `BANKISM_AMOUNT_SPIKE_RATIO_THRESHOLD` | `3.0` | Phase 3 ratio threshold (`amount / mean` and `amount / median`) for flagging amount spikes. |
| `BANKISM_VELOCITY_HOURLY_BURST_THRESHOLD` | `3` | Phase 3 1-hour transfer count threshold for flagging rapid velocity bursts. |
| `BANKISM_VELOCITY_DAILY_BURST_THRESHOLD` | `8` | Phase 3 24-hour transfer count threshold for flagging daily velocity surges. |
| `BANKISM_REPEATED_FAILED_ATTEMPTS_THRESHOLD` | `3` | Phase 3 24-hour rejected/blocked transfer attempt threshold for flagging probing behavior. |
| `BANKISM_RISK_ASSESSMENT_RETENTION_DAYS` | `90` | Phase 3 retention window (days) for persisted behavioral risk assessments. |

### 2.2 Feature Flags & Security Guardrails (Documented Development Defaults)
| Environment Variable | Default | Purpose |
| :--- | :--- | :--- |
| `BANKISM_ALLOW_TRANSACTION_EXECUTION` | `false` | Phase 1 safety flag. Note: `/firewall/inspect` permanently enforces `execution_permitted=False` in code regardless of this setting. |
| `BANKISM_ENABLE_HEURISTIC_DETECTION` | `true` | Enables obfuscation, zero-width character, and symbol-entropy heuristics in the AI Firewall. |
| `BANKISM_ENABLE_PAYMENT_METADATA_CHECKS` | `true` | Scans payment memos, account IDs, and actions for SQLi, XSS, command injection, and dangerous URIs. |
| `BANKISM_MASK_LOG_SENSITIVE_DATA` | `true` | Enforces PCI-DSS / GLBA masking of PAN card numbers, SSNs, and credentials in logs and outputs. |
| `BANKISM_HIGH_BEHAVIORAL_RISK_REQUIRES_DUAL_APPROVAL` | `true` | Escalates `HIGH` and `CRITICAL` behavioral risk transfers to mandatory `PENDING_DUAL_APPROVAL`. |
| `BANKISM_ENABLE_TOCTOU_WATERMARK_CHECK` | `true` | Re-verifies the account's historical ledger watermark inside the executor before consuming a single-approval ticket. |

### 2.3 Optional Runtime Settings
| Environment Variable | Default | Purpose |
| :--- | :--- | :--- |
| `BANKISM_ENV` / `BANKISM_ENVIRONMENT` | `development` | Runtime environment label (`development`, `testing`, `staging`, `production`). |
| `BANKISM_DEBUG` | `false` | FastAPI / Uvicorn debug reload flag. |
| `BANKISM_HOST` | `0.0.0.0` | Backend HTTP bind address. |
| `BANKISM_PORT` | `8000` | Backend HTTP bind port. |
| `BANKISM_DATABASE_PATH` | `bankism_ledger.db` | Local SQLite database file path. |
| `BANKISM_BEHAVIORAL_POLICY_VERSION` | `phase3-v1.0.0` | Version tag stamped onto every behavioral risk assessment. |

### 2.4 Internal Sandbox Signing Key (`BANKISM_HMAC_SECRET`)
- **What it is used for:** `BANKISM_HMAC_SECRET` (`Settings.hmac_secret`) is an internal HMAC-SHA256 signing key used solely by the local sandbox (`tickets.py`, `dual_approval.py`, `executor.py`) to sign and verify `AuthorizationTicket` tokens so transfer parameters cannot be tampered with between authorization and execution.
- **No external service dependency:** It is **not** an external API key. In local development, `config.py` provides an isolated default (`"bankism-dev-hmac-secret-key-32bytes-min-isolated"`) so the application starts and runs all features without manual secret entry.
- **Fail-closed preservation:** If an empty or `< 16`-character signing key is passed to `create_authorization_ticket()` or `verify_ticket_integrity()`, the system immediately raises a `ValueError` and fails closed (`test_missing_signing_key_fails_closed`). Furthermore, `Settings.ignore_blank_env_strings` ensures that blank environment entries (such as `BANKISM_PORT=`) fall back cleanly to documented defaults rather than crashing startup.

---

## 3. Architecture & Data Model Additions (Phase 3.1 – 3.5)

### 3.1 SQLite Schema Migration (`version = 2` in `bankism/backend/app/ledger/db.py`)
Idempotent migration v2 preserves all Phase 2 tables (`accounts`, `simulated_transactions`, `consumed_tickets`, `dual_approval_requests`, `tamper_evident_audit_logs`) and adds:
1. **`risk_assessments`**: Persists every behavioral evaluation (`assessment_id`, `user_id`, `source_account_id`, `destination_account_id`, `amount_cents`, `currency`, `transaction_fingerprint`, `profile_status`, `risk_score`, `risk_level`, `threat_tier`, `confidence`, `recommended_action`, `policy_action`, `recommended_action_reason`, `factors_json`, `baseline_snapshot_json`, `history_watermark`, `model_version`, `final_outcome`, `audit_event_hash`, `evaluated_at`).
2. **`transfer_attempts`**: Tracks prepared, validation-rejected, firewall-blocked, and dual-approval-escalated transfer attempts per user and source account so repeated probing or failed/blocked attempts within 24 hours are surfaced as a behavioral signal (`REPEATED_FAILED_OR_BLOCKED_ATTEMPTS`).

### 3.2 Baseline Feature Extraction & Honest Scope Limitations
Computed strictly from local SQLite tables (`simulated_transactions` and `transfer_attempts`) for the authenticated principal:
- **Sample Size & Cold Start:** `transaction_count`, `profile_status` (`INSUFFICIENT_HISTORY` when `< 3` completed transfers; `ESTABLISHED` when `>= 3`).
- **Central Tendency & Dispersion:** `mean_amount_cents`, `median_amount_cents`, `std_amount_cents`, `iqr_amount_cents`, `min_amount_cents`, `max_amount_cents`.
- **Deviation Metrics:** `amount_to_mean_ratio`, `amount_to_median_ratio`, `amount_z_score` (including low-variance constant-amount split/probe safeguard).
- **Multi-Window Velocity:** `tx_count_last_10m`, `tx_count_last_1h`, `tx_count_last_24h`, `tx_count_last_7d`, `total_outflow_24h_cents`, `avg_daily_tx_count_30d`, `velocity_24h_vs_30d_ratio`.
- **Counterparty & Temporal Signals:** `known_counterparties`, `is_novel_counterparty`, `recipient_prior_tx_count`, `recipient_tx_share`, `typical_hours_utc`, `recent_failed_or_blocked_24h`.
- **Documented Scope Limitations (`FEATURE_LIMITATIONS_DOC`):** Device fingerprint, geolocation/ASN, merchant category code (MCC), and session token age are explicitly documented as out-of-scope rather than fabricated.

### 3.3 Explainable Scoring Engine & Category Deduplication (`bankism/backend/app/profiling/engine.py`)
- **Bounded 0–100 Score:** Every triggered `RiskFactor` records `name`, `category`, `weight`, `score`, `observed_fact`, `inference`, `description`, and `evidence`.
- **No Correlated Double-Counting:** Signals are grouped by orthogonal category (`AMOUNT`, `VELOCITY`, `COUNTERPARTY`, `TEMPORAL`, `ATTEMPTS`, `COLD_START`, `FAIL_SAFE`). Within any single category, only the highest-scoring signal contributes to the composite score (`test_correlated_signals_not_double_counted`).
- **Multi-Signal Convergence Bonus:** When 2 or more independent non-trivial risk categories (`score >= 15.0`) co-occur (e.g., `NOVEL_COUNTERPARTY` + `AMOUNT_SPIKE_ANOMALY`), a bounded `MULTI_SIGNAL_CONVERGENCE` factor is added (`+8.0` for 2 categories, `+15.0` for 3+ categories).
- **Versioned Policy Mapping (`phase3-v1.0.0`):**
  - `0.0 – 24.9` → `LOW` (`STANDARD`) → `ALLOW_UNDER_EXISTING_POLICY` (`ALLOW`)
  - `25.0 – 49.9` → `MEDIUM` (`ELEVATED`) → `STEP_UP_REVIEW` (`STEP_UP_AUTH`)
  - `50.0 – 74.9` → `HIGH` (`HIGH_RISK`) → `REQUIRE_DUAL_APPROVAL` (`DUAL_APPROVAL`)
  - `75.0 – 100.0` → `CRITICAL` (`CRITICAL_RISK`) → `HOLD_FOR_TRUSTED_REVIEW` (`DUAL_APPROVAL`)

### 3.4 Risk-Aware Authorization & TOCTOU Watermark Protection
- **Strict Escalation Only:** In `AuthorizationService.prepare_transfer_authorization`, a firewall `BLOCK` immediately aborts before any ticket can be issued; a firewall `REVIEW` or static high amount (`>= $10,000`) always requires dual approval even if behavioral risk is `0.0 (LOW)`.Conversely, `HIGH` or `CRITICAL` behavioral risk escalates a sub-threshold transfer (e.g. `$2,500`) to `PENDING_DUAL_APPROVAL`.
- **Fail-Safe Exception Handling:** If `assess_transaction_risk` raises an exception or encounters malformed/inconsistent data, `_build_fail_safe_assessment` returns a `CRITICAL` (`85.0`) assessment with `HOLD_FOR_TRUSTED_REVIEW`, routing the transfer to `PENDING_DUAL_APPROVAL` (`test_risk_engine_exception_fails_safely_to_dual_approval`).
- **TOCTOU Watermark Enforcement:** Every assessment records a deterministic `history_watermark` (`{tx_count}:{latest_tx_id}:{count_1h}:{count_24h}`). When `SimulatedTransactionExecutor.execute_transfer` consumes a single-approval ticket, it compares the current account watermark against the assessment's watermark; if intervening activity occurred that escalates the transfer to `HIGH`/`CRITICAL` risk, execution is rejected fail-closed (`test_toctou_history_watermark_drift_invalidates_stale_ticket`).

---

## 4. Synthetic Evaluation & Calibration Results (`seed = 42`)

Implemented in `bankism/backend/app/risk/evaluation.py` (`run_synthetic_calibration_suite(seed=42)`). Note: These metrics measure **alignment against synthetic scenario labels** in an isolated temporary SQLite database, not real-world production fraud-detection accuracy.

| ID | Scenario Family | Profile Status | Score | Risk Level | Policy Recommendation | Expected Escalation | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SCEN-01` | Normal Routine Activity | `ESTABLISHED` | `5.0` | `LOW` | `ALLOW_UNDER_EXISTING_POLICY` | `False` | **TN (Aligned)** |
| `SCEN-02` | Benign Large Known-Recipient Purchase | `ESTABLISHED` | `15.0` | `LOW` | `ALLOW_UNDER_EXISTING_POLICY` | `False` | **TN (Aligned)** |
| `SCEN-03` | First Transfer to New Recipient | `ESTABLISHED` | `30.0` | `MEDIUM` | `STEP_UP_REVIEW` | `True` | **TP (Aligned)** |
| `SCEN-04` | Sudden Sharp Amount Spike (25x Baseline) | `ESTABLISHED` | `65.0` | `HIGH` | `REQUIRE_DUAL_APPROVAL` | `True` | **TP (Aligned)** |
| `SCEN-05` | Rapid Multi-Transfer Velocity Burst (1h) | `ESTABLISHED` | `60.0` | `HIGH` | `REQUIRE_DUAL_APPROVAL` | `True` | **TP (Aligned)** |
| `SCEN-06` | Repeated Rejected/Blocked Probing Attempts | `ESTABLISHED` | `53.0` | `HIGH` | `REQUIRE_DUAL_APPROVAL` | `True` | **TP (Aligned)** |
| `SCEN-07` | Multi-Signal High-Risk Convergence | `ESTABLISHED` | `98.0` | `CRITICAL` | `HOLD_FOR_TRUSTED_REVIEW` | `True` | **TP (Aligned)** |
| `SCEN-08` | Sparse-History Cold-Start User (1 Prior Tx) | `INSUFFICIENT_HISTORY` | `12.0` | `LOW` | `ALLOW_UNDER_EXISTING_POLICY` | `False` | **TN (Aligned)** |

- **Summary Metrics (Seed = 42):** `8 / 8` scenarios aligned (`5` True Positives, `3` True Negatives, `0` False Positives, `0` False Negatives).

---

## 5. Verification & Test Suite Summary

Run the complete backend verification suite with:
```bash
python3 -m pytest bankism/backend/tests -v
```

- **`test_phase3_profiling.py` (24 tests):** Covers golden rules, cold-start boundaries (`0, 1, 2, 3` transfers), amount spikes, 1h velocity bursts, novel counterparties, off-hours activity, category deduplication, multi-signal convergence, cross-user profile/assessment isolation (`403 Forbidden`), read-only API enforcement (`405 Method Not Allowed`), firewall `BLOCK`/`REVIEW` precedence, self-approval rejection on risk-escalated transfers, low-risk ticket tampering/replay rejection, TOCTOU watermark drift rejection, fail-safe exception handling, schema migration survival, blank-env configuration resilience, and deterministic synthetic calibration (`seed=42`).
- **`test_phase2_sandbox.py` (16 tests) & `test_phase2_audit_regression.py` (12 tests):** All 28 Phase 2 sandbox, ledger, dual-approval, and tamper-evident audit tests pass without modification.
- **Phase 1 Firewall & Invariant Tests (45 tests):** All 45 Phase 1 tests pass without modification.
