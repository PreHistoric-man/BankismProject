# BANKISM — PRODUCT SUITE & ADAPTIVE TRUST ENGINE MASTER REPORT

**Target System:** Bankism Dual Product Architecture: Bankism AI & Bankism Sentinel  
**Runtime:** Node.js 22 Full-Stack Express Server with Vite Frontend Integration  
**Frontend Stack:** React 19, TypeScript, Tailwind CSS, Lucide Icons  
**Security Gateway:** Deterministic AI Firewall, HMAC-SHA256 Token Issuer, Adaptive Trust Engine, SHA-256 Tamper-Evident Ledger  
**Status:** **OPERATIONAL, VERIFIED, & READY FOR DEMO (48/48 TESTS PASSING — 100% PASS RATE)**

---

## 1. Adaptive Trust Engine Architecture

The **Adaptive Trust Engine** extends Bankism's defense-in-depth architecture with transaction-specific behavioral risk intelligence. It calculates personal baselines, detects multi-dimensional anomalies, deduplicates correlated signals, and produces explainable advisory telemetry without compromising core authorization boundaries.

### 1.1 Personal Baseline Features Used
For each authenticated user, a personal baseline is computed strictly from that user's own eligible historical transactions:
- **Strict Identity Isolation:** Only transactions where `user_id === authenticated_principal` are analyzed. No cross-user data pooling.
- **Completed-Transaction Eligibility Filter:** Excludes `BLOCKED_FIREWALL`, `REJECTED_VALIDATION`, `PENDING`, or fraudulent transactions from baseline metrics.
- **Target Transaction Exclusion:** The proposed transaction being evaluated is prevented from leaking into its own baseline via explicit `excludeTxId` filtering.
- **Central Tendency:**
  - **Mean Transaction Amount:** Calculated in integer minor units (paise) to eliminate floating-point drift.
  - **Median Transaction Amount:** Computed using exact sorted midpoint analysis.
- **Variability & Robust Deviation:**
  - **Sample Standard Deviation ($\sigma$):** Computed using $N - 1$ degrees of freedom.
  - **Median Absolute Deviation (MAD):** Robust non-parametric dispersion measure less sensitive to legitimate outlier transfers.
- **Counterparty & Recipient Familiarity:**
  - Historical counterparty set for the user.
  - Number of previous transfers to the proposed recipient (`recipient_previous_transfers`).
  - Novel recipient flag (`is_new_recipient`).
- **Velocity Metrics:**
  - Rolling 1-hour burst count (`velocity_1h`).
  - Rolling 24-hour transaction frequency (`velocity_24h`).
- **Attempt History:**
  - Rolling 24-hour failed/blocked attempt count (`failed_attempts_24h`).

---

## 2. Scoring, Categories & Multi-Signal Convergence

### 2.1 Deterministic Bounded Scoring (0–100)
All scores are deterministic, bounded between 0 and 100, and align with Bankism's unified category boundaries:
- **LOW (0–24.9):** `ALLOW_UNDER_EXISTING_POLICY` — Transaction aligns with baseline; single HMAC ticket authorized.
- **MEDIUM (25–49.9):** `STEP_UP_REVIEW` — Moderate novelty (e.g., unfamiliar recipient); step-up audit logged.
- **HIGH (50–74.9):** `REQUIRE_DUAL_APPROVAL` — Elevated anomaly (e.g., rapid velocity or high value); mandates secondary Risk Officer sign-off.
- **CRITICAL (75–100):** `HOLD_FOR_TRUSTED_REVIEW` — Severe anomaly or multi-signal convergence; held fail-closed for supervisory approval.

### 2.2 Category Deduplication
Signals are categorized into orthogonal domains: `AMOUNT`, `VELOCITY`, `COUNTERPARTY`, `ATTEMPTS`, `TIMING`, and `COLD_START`.  
To prevent collinear signals (e.g., amount ratio vs. amount z-score) from double-counting, the engine groups signals by category and takes only the maximum score within each category:
$$\text{CategoryScore}(C) = \max_{s \in \text{Signals}(C)} \text{Score}(s)$$

### 2.3 Multi-Signal Convergence Bonus
When multiple orthogonal risk categories co-occur with significant severity (score $\ge 20$):
- **2 Significant Categories:** $+8.0$ convergence bonus.
- **3+ Significant Categories:** $+15.0$ convergence bonus.
- **Composite Formulation:**
$$\text{Composite} = \min\left(98.0, \; \text{Score}_{\text{primary}} + 0.25 \times \sum \text{Score}_{\text{secondary}} + \text{Bonus}_{\text{convergence}}\right)$$

### 2.4 Baseline Maturity & Confidence
- **Cold-Start ($<3$ transfers):** `COLD_START` maturity, `INSUFFICIENT_HISTORY` profile status, conservative baseline confidence of **35%**.
- **Developing ($3–5$ transfers):** `DEVELOPING` maturity, `ESTABLISHED` profile status, confidence **55%–75%**.
- **Established ($\ge 6$ transfers):** `ESTABLISHED` maturity, `ESTABLISHED` profile status, confidence **75%–98%**.

---

## 3. Handling of Cold-Start Users

1. **Non-Punitive Baseline:** New users with $<3$ completed transfers are flagged with `profile_status = INSUFFICIENT_HISTORY` and an informational `INSUFFICIENT_HISTORY` signal ("There is not enough transaction history to establish a reliable baseline.").
2. **Routine Transfers Allowed:** A routine, low-value transfer (e.g., ₹4,500) during cold start produces a minimal score of 5.0 (LOW) and is **never** falsely classified as malicious.
3. **High-Value Protection:** If an unestablished profile requests a large transfer ($\ge ₹50,000$), the engine raises `COLD_START_HIGH_VALUE` (score 55.0, HIGH), routing it to Dual Approval without misclassifying it as prompt injection.

---

## 4. Contributing Signals Exposed to the UI

Every detected signal provides a stable ID, human-readable name, severity, bounded contribution score, concise explanation, and factual evidence:

| Signal ID | Human-Readable Name | Category | Explanation | Typical Evidence |
|---|---|---|---|---|
| `AMOUNT_SPIKE_ANOMALY` | Amount Spike Anomaly | `AMOUNT` | *"Amount is significantly above your usual transfer range."* | `deviation_ratio: 15.0x`, `z_score: 177.0`, `mean_rupees: 10,000` |
| `NOVEL_COUNTERPARTY` | New Recipient | `COUNTERPARTY` | *"This is a new recipient."* | `recipient: ACC-3003-BUS`, `prior_transfers: 0` |
| `INITIAL_COUNTERPARTY` | Initial Counterparty | `COUNTERPARTY` | *"First transfer to this recipient during account baseline establishment."* | `is_cold_start: true` |
| `RAPID_VELOCITY_BURST_1H` | Rapid Transfer Velocity | `VELOCITY` | *"Recent transfer frequency is unusually high."* | `transfers_last_hour: 4`, `threshold: 3` |
| `REPEATED_FAILED_ATTEMPTS` | Repeated Failed Attempts | `ATTEMPTS` | *"Multiple rejected or blocked transactions recorded in the past 24 hours."* | `failed_attempts_24h: 3`, `threshold: 3` |
| `OFF_HOURS_ACTIVITY` | Off-Hours Activity | `TIMING` | *"Transaction initiated during unusual overnight hours (01:00–05:00 UTC)."* | `window: 01:00-05:00 UTC` |
| `INSUFFICIENT_HISTORY` | Sparse Baseline | `COLD_START` | *"There is not enough transaction history to establish a reliable baseline."* | `completed_transfers: 1`, `required: 3` |

### 4.1 UI Integration Points
- **Bankism AI (`/app`):** When a transaction proposal requires dual approval, the card renders the exact concise bulleted explanations from the assessment (e.g. *"Amount is significantly above your usual transfer range."*, *"This is a new recipient."*).
- **Bankism Sentinel (`/sentinel`):**
  - **Pending Approvals Queue:** Displays risk level badge (CRITICAL / HIGH), score, baseline confidence, and chips for each contributing signal.
  - **Forensic Telemetry Evidence Modal:** Displays a dedicated Adaptive Trust Engine section with baseline maturity, confidence, analyzed transactions, and full signal breakdowns with evidence facts.

---

## 5. Security Boundary & Invariants

The Adaptive Trust Engine is strictly **advisory** and never acts as an authorization mechanism. The following invariants were verified under red-team conditions:
1. **Firewall Priority:** A firewall `BLOCK` (prompt injection, jailbreak, SQLi metadata) **always** halts the transfer fail-closed, even if the behavioral risk score is 0.
2. **Authorization Preconditions:** A low risk score can **never** bypass authentication, account ownership, ledger balance checks, daily limits, or dual-approval mandates.
3. **Execution Separation:** Assessing a proposed transaction **never** moves funds or debits balances. Only ticket confirmation with a valid HMAC signature updates the ledger.
4. **Client Isolation:** Client-supplied risk scores or claims in request payloads are strictly discarded server-side in favor of authenticated principal evaluation.
5. **Separation of Duties:** The transaction initiator can never sign off on their own held transaction.

---

## 6. Verification & Test Suite Results

The comprehensive test suite in `tests/red_team_verification.ts` executes **48 discrete tests** across 7 priority domains. All tests were executed and observed passing:

```
==============================================================================
BANKISM PHASE 3 FINAL RED-TEAM VERIFICATION RESULTS
==============================================================================
[P1-01] ✓ PASS   | [Priority 1] Firewall BLOCK always prevents ticket issuance even with low behavioral risk
[P1-02] ✓ PASS   | [Priority 1] Firewall REVIEW cannot execute directly without trusted clearance
[P1-03] ✓ PASS   | [Priority 1] Low behavioral risk cannot bypass account ownership checks
[P1-04] ✓ PASS   | [Priority 1] Low behavioral risk cannot bypass ledger balance sufficiency
[P1-05] ✓ PASS   | [Priority 1] HIGH and CRITICAL behavioral assessments enforce dual approval / hold policy
[P1-06] ✓ PASS   | [Priority 1] Dual approval requires a distinct authorized approver (prohibits self-approval)
[P1-07] ✓ PASS   | [Priority 1] Modifying amount, destination, or initiator invalidates HMAC ticket signature
[P1-08] ✓ PASS   | [Priority 1] Expired, forged, or replayed tickets are rejected fail-closed
[P1-09] ✓ PASS   | [Priority 1] Concurrent confirmation attempts cannot double-spend (atomic single consumption)
[P1-10] ✓ PASS   | [Priority 1] Stale TOCTOU watermark drift invalidates single-approval ticket fail-closed
[P2-01] ✓ PASS   | [Priority 1] Cross-user profile access blocked (Alice cannot read Bob private profile)
[P2-02] ✓ PASS   | [Priority 2] Client-supplied user_id in payload is strictly ignored in favor of verified server principal
[P2-03] ✓ PASS   | [Priority 2] Client-supplied risk_score or profile_status in payload is discarded
[P2-04] ✓ PASS   | [Priority 2] Attempt history cannot be fabricated through untrusted input
[P3-01] ✓ PASS   | [Priority 3] Deterministic scoring and bounded 0-100 score across all edge inputs
[P3-02] ✓ PASS   | [Priority 3] Category boundaries test (<25 LOW, 25-49.9 MEDIUM, 50-74.9 HIGH, 75-100 CRITICAL)
[P3-03] ✓ PASS   | [Priority 3] Category deduplication prevents collinear signal double-counting
[P3-04] ✓ PASS   | [Priority 3] Cold-start behavior (<3 transfers) yields INSUFFICIENT_HISTORY and conservative confidence
[P3-05] ✓ PASS   | [Priority 3] Multi-signal convergence bonus triggered when 2+ orthogonal risk categories co-occur
[P3-06] ✓ PASS   | [Priority 3] Synthetic calibration suite reproduces 8/8 scenario alignments (seed=42)
[P4-01] ✓ PASS   | [Priority 4] Unbroken SHA-256 genesis-to-head hash sequence verifies successfully
[P4-02] ✓ PASS   | [Priority 4] Modifying an intermediate audit event payload or hash breaks chain detection
[P4-03] ✓ PASS   | [Priority 4] Deleting or reordering audit records breaks chain verification
[P4-04] ✓ PASS   | [Priority 4] Ledger and ticket atomicity: failed execution leaves balances unchanged
[P5-01] ✓ PASS   | [Priority 5] [Sentinel] Event filtering strictly segments blocked, review, and completed audit entries
[P5-02] ✓ PASS   | [Priority 5] [Bankism AI] Read-only balance & transaction queries strictly produce zero ledger mutations
[P5-03] ✓ PASS   | [Priority 5] [Bankism AI] Conversational transfer proposal requires explicit client confirmation card before execution
[P5-04] ✓ PASS   | [Priority 5] [Bankism AI] Hostile prompt injection in chat is intercepted by firewall with zero money moved
[P5-05] ✓ PASS   | [Priority 5] [Sentinel SOC] High-value transfer ($15k) enforces dual-approval separation of duties
[P6-01] ✓ PASS   | [Priority 6] INR currency formatter uses en-IN locale with Indian digit grouping (e.g. ₹1,50,000.00)
[P6-02] ✓ PASS   | [Priority 6] Backend monetary semantics strictly use integer paise with zero floating-point drift
[P6-03] ✓ PASS   | [Priority 6] Legitimate high-value transfer (₹1,50,000) enters safe REVIEW/DUAL_APPROVAL without prompt injection misclassification
[P6-04] ✓ PASS   | [Priority 6] Hostile prompt injection BLOCK cannot be bypassed by high value, low risk, or claimed approval
[P6-05] ✓ PASS   | [Priority 6] Canonical transaction verification strictly enforces INR currency match
[ATE-01] ✓ PASS   | [Priority 7] User-specific baselines do not leak across users
[ATE-02] ✓ PASS   | [Priority 7] Cold-start status and confidence are correct
[ATE-03] ✓ PASS   | [Priority 7] Historical baselines exclude the transaction being evaluated
[ATE-04] ✓ PASS   | [Priority 7] Blocked, pending, and failed transactions do not distort completed-transfer baselines
[ATE-05] ✓ PASS   | [Priority 7] Legitimate large transaction is flagged as anomalous or routed for review, not prompt injection
[ATE-06] ✓ PASS   | [Priority 7] A new recipient produces an explainable signal
[ATE-07] ✓ PASS   | [Priority 7] Unusual transfer velocity produces an explainable signal
[ATE-08] ✓ PASS   | [Priority 7] Duplicate or correlated signals do not artificially inflate the score
[ATE-09] ✓ PASS   | [Priority 7] Scores are deterministic and always bounded between 0 and 100
[ATE-10] ✓ PASS   | [Priority 7] A low score cannot override a firewall BLOCK
[ATE-11] ✓ PASS   | [Priority 7] A low score cannot bypass ownership, balance, limits, or dual approval
[ATE-12] ✓ PASS   | [Priority 7] Client-supplied scores cannot influence authorization
[ATE-13] ✓ PASS   | [Priority 7] Failed or pending assessments do not mutate ledger balances
[ATE-14] ✓ PASS   | [Priority 7] Existing authorization ticket and audit invariants continue to pass
------------------------------------------------------------------------------
TOTAL TESTS: 48 | PASSED: 48 | FAILED: 0
==============================================================================
```

### 6.1 Build and Type Check Results
- **TypeScript Typecheck (`tsc --noEmit`):** Passed with 0 errors.
- **Production Build (`vite build`):** Compiled successfully (`dist/` generated with clean chunks).

---

## 7. Known Limitations

1. **Small Sample Size Sensitivity:** In demo or newly provisioned environments with small history sizes ($N = 3–5$), sample standard deviation has higher variance. The engine includes robust Median Absolute Deviation (MAD) and conservative confidence calibration to prevent overconfidence on small samples.
2. **In-Memory Volatility:** Historical records, pending approvals, and audit hashes reside in memory in this prototype container. Reboots reset history to the seeded ledger.
3. **Linear Counterparty Tracking:** Counterparty familiarity is tracked by recipient account ID matching without external banking directory graph linkage.
4. **Time Window Resolution:** Velocity metrics rely on historical `hours_ago` timestamps; microsecond-interval burst detection is bounded by event resolution.
