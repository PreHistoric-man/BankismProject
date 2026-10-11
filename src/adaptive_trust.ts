/**
 * @file adaptive_trust.ts
 * @description Bankism Adaptive Trust Engine
 *
 * Implements transaction-specific behavioral risk assessment:
 * 1. Personal transaction baselines (mean, median, robust deviation, velocity, recipient history)
 * 2. Transaction-specific anomaly signals (amount deviation, new counterparty, velocity bursts)
 * 3. Deterministic bounded scoring (0-100) with category deduplication & multi-signal convergence
 * 4. Explainable advisory telemetry strictly separated from authorization mechanisms
 */

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ProfileStatus = 'ESTABLISHED' | 'INSUFFICIENT_HISTORY';
export type BaselineMaturity = 'COLD_START' | 'DEVELOPING' | 'ESTABLISHED';
export type BehavioralPolicyAction =
  | 'ALLOW_UNDER_EXISTING_POLICY'
  | 'STEP_UP_REVIEW'
  | 'REQUIRE_DUAL_APPROVAL'
  | 'HOLD_FOR_TRUSTED_REVIEW';

export type SignalCategory =
  | 'AMOUNT'
  | 'VELOCITY'
  | 'COUNTERPARTY'
  | 'ATTEMPTS'
  | 'TIMING'
  | 'COLD_START';

export interface ContributingSignal {
  id: string;
  name: string;
  category: SignalCategory;
  explanation: string;
  severity: RiskLevel;
  score: number;
  evidence: Record<string, any>;
}

export interface PersonalBaseline {
  user_id: string;
  total_eligible_transfers: number;
  mean_paise: number;
  mean_rupees: number;
  median_paise: number;
  median_rupees: number;
  std_paise: number;
  std_rupees: number;
  mad_paise: number; // Median Absolute Deviation
  mad_rupees: number;
  velocity_1h: number;
  velocity_24h: number;
  failed_attempts_24h: number;
  known_counterparties: string[];
  recipient_previous_transfers: number;
  is_new_recipient: boolean;
  baseline_maturity: BaselineMaturity;
  confidence: number; // 0.0 to 1.0
  profile_status: ProfileStatus;
}

export interface AdaptiveTrustAssessment {
  assessment_id: string;
  user_id: string;
  source_account_id: string;
  destination_account_id: string;
  amount_paise: number;
  amount_rupees: number;
  currency: 'INR';
  score: number;
  level: RiskLevel;
  profile_status: ProfileStatus;
  confidence: number;
  policy_action: BehavioralPolicyAction;
  baseline: PersonalBaseline;
  signals: ContributingSignal[];
  factors: string[]; // Stable signal IDs for backward compatibility
  explanations: string[];
  history_watermark: string;
  assessed_at: string;
}

export interface HistoricalTransactionRecord {
  tx_id?: string;
  user_id?: string;
  user?: string;
  source_account_id?: string;
  src?: string;
  destination_account_id?: string;
  dst?: string;
  amount_paise?: number;
  amount_cents?: number;
  amount_rupees?: number;
  currency?: string;
  status: 'COMPLETED' | 'BLOCKED_FIREWALL' | 'REJECTED_VALIDATION' | string;
  hours_ago?: number;
  created_at_utc?: string;
}

/**
 * Computes the personal transaction baseline from an authenticated user's own eligible transactions.
 * Excludes pending, blocked, or failed transactions, and excludes the transaction being assessed.
 */
export function computePersonalBaseline(
  userId: string,
  proposedDst: string,
  history: HistoricalTransactionRecord[],
  excludeTxId?: string
): PersonalBaseline {
  // 1. Strict identity isolation: only include this authenticated user's records
  const userTxs = history.filter((t) => {
    const owner = t.user_id || t.user;
    return owner === userId && (!excludeTxId || t.tx_id !== excludeTxId);
  });

  // 2. Eligibility filter: only COMPLETED transactions inform the baseline
  const eligible = userTxs.filter((t) => t.status === 'COMPLETED');
  const count = eligible.length;

  // 3. Amount metrics (using minor units paise / cents)
  const amounts = eligible
    .map((t) => t.amount_paise ?? t.amount_cents ?? (t.amount_rupees ? Math.round(t.amount_rupees * 100) : 0))
    .sort((a, b) => a - b);

  const meanPaise = count > 0 ? amounts.reduce((a, b) => a + b, 0) / count : 0;

  let medianPaise = 0;
  if (count > 0) {
    if (count % 2 === 1) {
      medianPaise = amounts[Math.floor(count / 2)];
    } else {
      medianPaise = (amounts[count / 2 - 1] + amounts[count / 2]) / 2;
    }
  }

  const variance =
    count > 1 ? amounts.reduce((acc, v) => acc + Math.pow(v - meanPaise, 2), 0) / (count - 1) : 0;
  const stdPaise = Math.sqrt(variance);

  // Robust deviation: Median Absolute Deviation (MAD)
  const absDeviations = amounts.map((a) => Math.abs(a - medianPaise)).sort((a, b) => a - b);
  let madPaise = 0;
  if (count > 0) {
    if (count % 2 === 1) {
      madPaise = absDeviations[Math.floor(count / 2)];
    } else {
      madPaise = (absDeviations[count / 2 - 1] + absDeviations[count / 2]) / 2;
    }
  }

  // 4. Recipient / Counterparty metrics
  const knownCounterparties = Array.from(
    new Set(eligible.map((t) => (t.destination_account_id || t.dst || '').trim()).filter(Boolean))
  );
  const normalizedDst = (proposedDst || '').trim();
  const recipientTxs = eligible.filter(
    (t) => (t.destination_account_id || t.dst || '').trim() === normalizedDst
  );
  const recipientPreviousTransfers = recipientTxs.length;
  const isNewRecipient = recipientPreviousTransfers === 0;

  // 5. Velocity metrics
  const velocity_1h = eligible.filter((t) => (t.hours_ago ?? 999) <= 1).length;
  const velocity_24h = eligible.filter((t) => (t.hours_ago ?? 999) <= 24).length;

  // 6. Ineligible attempt tracking (for attempt pattern signal)
  const failed_attempts_24h = userTxs.filter(
    (t) => t.status !== 'COMPLETED' && (t.hours_ago ?? 999) <= 24
  ).length;

  // 7. Baseline maturity and confidence calibration
  let baselineMaturity: BaselineMaturity = 'COLD_START';
  let profileStatus: ProfileStatus = 'INSUFFICIENT_HISTORY';
  let confidence = 0.35;

  if (count >= 6) {
    baselineMaturity = 'ESTABLISHED';
    profileStatus = 'ESTABLISHED';
    confidence = Math.min(0.98, Math.round((0.75 + (count - 6) * 0.04) * 100) / 100);
  } else if (count >= 3) {
    baselineMaturity = 'DEVELOPING';
    profileStatus = 'ESTABLISHED';
    confidence = Math.round((0.55 + (count - 3) * 0.1) * 100) / 100;
  } else {
    baselineMaturity = 'COLD_START';
    profileStatus = 'INSUFFICIENT_HISTORY';
    confidence = 0.35;
  }

  return {
    user_id: userId,
    total_eligible_transfers: count,
    mean_paise: Math.round(meanPaise),
    mean_rupees: Math.round(meanPaise) / 100,
    median_paise: Math.round(medianPaise),
    median_rupees: Math.round(medianPaise) / 100,
    std_paise: Math.round(stdPaise),
    std_rupees: Math.round(stdPaise) / 100,
    mad_paise: Math.round(madPaise),
    mad_rupees: Math.round(madPaise) / 100,
    velocity_1h,
    velocity_24h,
    failed_attempts_24h,
    known_counterparties: knownCounterparties,
    recipient_previous_transfers: recipientPreviousTransfers,
    is_new_recipient: isNewRecipient,
    baseline_maturity: baselineMaturity,
    confidence,
    profile_status: profileStatus,
  };
}

/**
 * Evaluates the proposed transaction against the user's personal baseline.
 * Produces deterministic, bounded (0-100) score with category deduplication and convergence.
 */
export function evaluateAdaptiveTrust(
  userId: string,
  srcAcc: string,
  dstAcc: string,
  amountPaise: number,
  history: HistoricalTransactionRecord[],
  options?: {
    offHours?: boolean;
    excludeTxId?: string;
    chainHeadHash?: string;
  }
): AdaptiveTrustAssessment {
  const baseline = computePersonalBaseline(userId, dstAcc, history, options?.excludeTxId);
  const signals: ContributingSignal[] = [];

  const isColdStart = baseline.profile_status === 'INSUFFICIENT_HISTORY';
  const amountRupees = amountPaise / 100;

  // Signal 1: AMOUNT Category (Normalized & Bounded)
  if (!isColdStart && baseline.mean_paise > 0) {
    const ratio = amountPaise / baseline.mean_paise;
    const zScore =
      baseline.std_paise > 0
        ? (amountPaise - baseline.mean_paise) / baseline.std_paise
        : (ratio - 1) * 2;

    if (zScore >= 2.5 || ratio >= 3.0) {
      const score = Math.min(90, Math.round((40 + ratio * 10 + Math.max(0, zScore) * 8) * 10) / 10);
      signals.push({
        id: 'AMOUNT_SPIKE_ANOMALY',
        name: 'Amount Spike Anomaly',
        category: 'AMOUNT',
        explanation: 'Amount is significantly above your usual transfer range.',
        severity: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : 'MEDIUM',
        score,
        evidence: {
          deviation_ratio: Math.round(ratio * 10) / 10,
          z_score: Math.round(zScore * 100) / 100,
          mean_rupees: baseline.mean_rupees,
          proposed_rupees: amountRupees,
        },
      });
    }
  } else if (isColdStart && amountPaise > 5000000) {
    // Large transfer on cold-start profile (₹50,000+)
    signals.push({
      id: 'COLD_START_HIGH_VALUE',
      name: 'High Value on Unestablished Profile',
      category: 'AMOUNT',
      explanation: 'Large transfer requested before an established transaction baseline exists.',
      severity: 'HIGH',
      score: 55.0,
      evidence: {
        proposed_rupees: amountRupees,
        prior_transfers: baseline.total_eligible_transfers,
      },
    });
  }

  // Signal 2: COUNTERPARTY Category
  if (baseline.is_new_recipient) {
    if (!isColdStart) {
      signals.push({
        id: 'NOVEL_COUNTERPARTY',
        name: 'New Recipient',
        category: 'COUNTERPARTY',
        explanation: 'This is a new recipient.',
        severity: 'MEDIUM',
        score: 35.0,
        evidence: {
          recipient: dstAcc,
          prior_transfers_to_recipient: 0,
          known_recipients_count: baseline.known_counterparties.length,
        },
      });
    } else {
      signals.push({
        id: 'INITIAL_COUNTERPARTY',
        name: 'Initial Counterparty',
        category: 'COUNTERPARTY',
        explanation: 'First transfer to this recipient during account baseline establishment.',
        severity: 'LOW',
        score: 5.0,
        evidence: {
          recipient: dstAcc,
          is_cold_start: true,
        },
      });
    }
  }

  // Signal 3: VELOCITY Category
  if (baseline.velocity_1h >= 3) {
    const vScore = Math.min(85, 45 + baseline.velocity_1h * 10);
    signals.push({
      id: 'RAPID_VELOCITY_BURST_1H',
      name: 'Rapid Transfer Velocity',
      category: 'VELOCITY',
      explanation: 'Recent transfer frequency is unusually high.',
      severity: vScore >= 75 ? 'CRITICAL' : 'HIGH',
      score: vScore,
      evidence: {
        transfers_in_past_hour: baseline.velocity_1h,
        threshold: 3,
      },
    });
  }

  // Signal 4: ATTEMPTS Category
  if (baseline.failed_attempts_24h >= 3) {
    const fScore = Math.min(75, 35 + baseline.failed_attempts_24h * 10);
    signals.push({
      id: 'REPEATED_FAILED_ATTEMPTS',
      name: 'Repeated Failed/Blocked Attempts',
      category: 'ATTEMPTS',
      explanation: 'Multiple rejected or blocked transactions recorded in the past 24 hours.',
      severity: fScore >= 75 ? 'CRITICAL' : 'HIGH',
      score: fScore,
      evidence: {
        failed_attempts_24h: baseline.failed_attempts_24h,
        threshold: 3,
      },
    });
  }

  // Signal 5: TIMING Category
  if (options?.offHours) {
    signals.push({
      id: 'OFF_HOURS_ACTIVITY',
      name: 'Off-Hours Activity',
      category: 'TIMING',
      explanation: 'Transaction initiated during unusual overnight hours (01:00–05:00 UTC).',
      severity: 'MEDIUM',
      score: 25.0,
      evidence: {
        window: '01:00-05:00 UTC',
      },
    });
  }

  // Signal 6: Cold-start baseline uncertainty notification (informational, bounded)
  if (isColdStart && signals.every((s) => s.category !== 'AMOUNT')) {
    signals.push({
      id: 'INSUFFICIENT_HISTORY',
      name: 'Sparse Transaction Baseline',
      category: 'COLD_START',
      explanation: 'There is not enough transaction history to establish a reliable baseline.',
      severity: 'LOW',
      score: 0.0,
      evidence: {
        eligible_transfers_recorded: baseline.total_eligible_transfers,
        minimum_required_for_maturity: 3,
      },
    });
  }

  // Deduplication: Pick the highest scoring signal in each category to prevent collinear double counting
  const categoryMax = new Map<SignalCategory, ContributingSignal>();
  for (const s of signals) {
    const current = categoryMax.get(s.category);
    if (!current || s.score > current.score) {
      categoryMax.set(s.category, s);
    }
  }

  const sortedCatSignals = Array.from(categoryMax.values()).sort((a, b) => b.score - a.score);

  // Composite score calculation with Multi-Signal Convergence
  let composite = 5.0;
  if (sortedCatSignals.length > 0 && sortedCatSignals[0].score > 0) {
    const primary = sortedCatSignals[0].score;
    const secondarySum = sortedCatSignals.slice(1).reduce((acc, s) => acc + s.score, 0);
    const sigCount = sortedCatSignals.filter((s) => s.score >= 20).length;
    const convergenceBonus = sigCount >= 2 ? (sigCount >= 3 ? 15.0 : 8.0) : 0.0;
    composite = Math.min(
      98.0,
      Math.max(0.0, Math.round((primary + secondarySum * 0.25 + convergenceBonus) * 10) / 10)
    );
  }

  // Determine Risk Level & Policy Action based on established project thresholds
  let level: RiskLevel = 'LOW';
  let policyAction: BehavioralPolicyAction = 'ALLOW_UNDER_EXISTING_POLICY';
  if (composite >= 75.0) {
    level = 'CRITICAL';
    policyAction = 'HOLD_FOR_TRUSTED_REVIEW';
  } else if (composite >= 50.0) {
    level = 'HIGH';
    policyAction = 'REQUIRE_DUAL_APPROVAL';
  } else if (composite >= 25.0) {
    level = 'MEDIUM';
    policyAction = 'STEP_UP_REVIEW';
  }

  // Extract human-readable explanations from actively contributing signals
  const explanations = signals
    .filter((s) => s.score > 0 || s.id === 'INSUFFICIENT_HISTORY')
    .map((s) => s.explanation);
  if (explanations.length === 0) {
    explanations.push('Transaction aligns with the authenticated user’s observed historical baseline.');
  }

  const headPart = options?.chainHeadHash ? options.chainHeadHash.slice(0, 10) : '0';
  const watermark = `wm_count${baseline.total_eligible_transfers}_head${headPart}`;
  const assessment_id = 'asm_' + Math.random().toString(36).substring(2, 12);

  return {
    assessment_id,
    user_id: userId,
    source_account_id: srcAcc,
    destination_account_id: dstAcc,
    amount_paise: amountPaise,
    amount_rupees: amountRupees,
    currency: 'INR',
    score: composite,
    level,
    profile_status: baseline.profile_status,
    confidence: baseline.confidence,
    policy_action: policyAction,
    baseline,
    signals,
    factors: sortedCatSignals.map((s) => s.id),
    explanations,
    history_watermark: watermark,
    assessed_at: new Date().toISOString(),
  };
}
