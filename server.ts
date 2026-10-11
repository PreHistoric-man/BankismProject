/**
 * @file server.ts
 * @description Bankism Full-Stack Node.js/Express Server
 * Implements the Defensive AI Security Firewall, Risk Engine, Authorization Gateway,
 * and Tamper-Evident SHA-256 Chained Audit Trail. Serves Vite SPA in development & production.
 * Denominated throughout in Indian Rupees (INR) with integer minor units (paise).
 */

import express, { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const CONFIG = {
  CURRENCY: 'INR' as const,
  // High-value policy threshold in paise: default ₹50,000.00 (50,00,000 paise)
  HIGH_VALUE_THRESHOLD_PAISE: Number(process.env.BANKISM_HIGH_AMOUNT_THRESHOLD) || 5000000,
  DUAL_APPROVAL_EXPIRY_SECONDS: Number(process.env.BANKISM_DUAL_APPROVAL_EXPIRY_SECONDS) || 300,
  TICKET_EXPIRY_SECONDS: Number(process.env.BANKISM_TICKET_EXPIRY_SECONDS) || 300,
  HMAC_SECRET: process.env.BANKISM_HMAC_SECRET || 'bankism-production-secure-hmac-secret-key-32bytes-min',
};
const HMAC_SECRET = CONFIG.HMAC_SECRET;

export function formatINR(amountRupees: number): string {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 2,
    minimumFractionDigits: 2,
  }).format(amountRupees);
}

export function formatPaiseToINR(amountPaise: number): string {
  return formatINR(amountPaise / 100);
}

app.use(express.json());

// Enable CORS for local testing if needed
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Bankism-Mock-User');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ============================================================================
// Types & Directory
// ============================================================================
type Verdict = 'APPROVE' | 'BLOCK' | 'REVIEW';
type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type ProfileStatus = 'ESTABLISHED' | 'INSUFFICIENT_HISTORY';
type BehavioralPolicyAction =
  | 'ALLOW_UNDER_EXISTING_POLICY'
  | 'STEP_UP_REVIEW'
  | 'REQUIRE_DUAL_APPROVAL'
  | 'HOLD_FOR_TRUSTED_REVIEW';

interface Principal {
  user_id: string;
  username: string;
  role: 'CUSTOMER' | 'APPROVER';
  authorized_accounts: string[];
}

const DEMO_DIRECTORY: Record<string, Principal> = {
  alice: {
    user_id: 'USR-4401-ALICE',
    username: 'alice',
    role: 'CUSTOMER',
    authorized_accounts: ['ACC-1001-CHK', 'ACC-2002-SAV'],
  },
  bob: {
    user_id: 'USR-8899-BOB',
    username: 'bob',
    role: 'CUSTOMER',
    authorized_accounts: ['ACC-3003-BUS'],
  },
  charlie: {
    user_id: 'USR-9900-CHARLIE',
    username: 'charlie',
    role: 'APPROVER',
    authorized_accounts: [],
  },
  dave: {
    user_id: 'USR-1100-DAVE',
    username: 'dave',
    role: 'CUSTOMER',
    authorized_accounts: ['ACC-4004-CHK'],
  },
};

function resolvePrincipal(req: Request): Principal {
  let userHeader = (req.headers['x-bankism-mock-user'] as string) || '';
  if (!userHeader) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      userHeader = authHeader.substring(7).trim();
    }
  }
  const clean = userHeader.trim().toLowerCase();
  const principal = DEMO_DIRECTORY[clean];
  if (!principal) {
    throw { status: 401, message: `INVALID_PRINCIPAL: '${userHeader}' not recognized.` };
  }
  return principal;
}

// ============================================================================
// In-Memory Data Store (Fictional Indian Rupee Accounts & History in Paise)
// ============================================================================
interface AccountRecord {
  account_id: string;
  name: string;
  owner_user_id: string;
  balance_paise: number;
  daily_limit_paise: number;
  currency: 'INR';
  // Backward-compatibility aliases
  balance_cents: number;
  daily_limit_cents: number;
}

const accountsStore: Map<string, AccountRecord> = new Map([
  [
    'ACC-1001-CHK',
    {
      account_id: 'ACC-1001-CHK',
      name: 'Everyday Checking',
      owner_user_id: 'USR-4401-ALICE',
      balance_paise: 25000000, // ₹2,50,000.00 (2,50,00,000 paise)
      daily_limit_paise: 50000000, // ₹5,00,000.00
      currency: 'INR',
      balance_cents: 25000000,
      daily_limit_cents: 50000000,
    },
  ],
  [
    'ACC-2002-SAV',
    {
      account_id: 'ACC-2002-SAV',
      name: 'High-Yield Savings',
      owner_user_id: 'USR-4401-ALICE',
      balance_paise: 150000000, // ₹15,00,000.00 (15,00,00,000 paise)
      daily_limit_paise: 250000000, // ₹25,00,000.00
      currency: 'INR',
      balance_cents: 150000000,
      daily_limit_cents: 250000000,
    },
  ],
  [
    'ACC-3003-BUS',
    {
      account_id: 'ACC-3003-BUS',
      name: 'Commercial Operating',
      owner_user_id: 'USR-8899-BOB',
      balance_paise: 750000000, // ₹75,00,000.00 (75,00,00,000 paise)
      daily_limit_paise: 500000000, // ₹50,00,000.00
      currency: 'INR',
      balance_cents: 750000000,
      daily_limit_cents: 500000000,
    },
  ],
  [
    'ACC-4004-CHK',
    {
      account_id: 'ACC-4004-CHK',
      name: 'Standard Checking',
      owner_user_id: 'USR-1100-DAVE',
      balance_paise: 10000000, // ₹1,00,000.00 (1,00,00,000 paise)
      daily_limit_paise: 20000000, // ₹2,00,000.00
      currency: 'INR',
      balance_cents: 10000000,
      daily_limit_cents: 20000000,
    },
  ],
]);

interface HistoricalTransaction {
  tx_id: string;
  user_id: string;
  source_account_id: string;
  destination_account_id: string;
  amount_paise: number;
  amount_cents: number;
  currency: 'INR';
  memo: string;
  status: 'COMPLETED' | 'BLOCKED_FIREWALL' | 'REJECTED_VALIDATION';
  created_at_utc: string;
  hours_ago: number;
  audit_event_hash?: string;
}

const historicalTransactionsStore: HistoricalTransaction[] = [
  { tx_id: 'tx_hist_a1', user_id: 'USR-4401-ALICE', source_account_id: 'ACC-1001-CHK', destination_account_id: 'ACC-2002-SAV', amount_paise: 1000000, amount_cents: 1000000, currency: 'INR', memo: 'Routine savings deposit', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 120 * 3600000).toISOString(), hours_ago: 120 },
  { tx_id: 'tx_hist_a2', user_id: 'USR-4401-ALICE', source_account_id: 'ACC-1001-CHK', destination_account_id: 'ACC-2002-SAV', amount_paise: 950000, amount_cents: 950000, currency: 'INR', memo: 'Weekly allocation', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 96 * 3600000).toISOString(), hours_ago: 96 },
  { tx_id: 'tx_hist_a3', user_id: 'USR-4401-ALICE', source_account_id: 'ACC-1001-CHK', destination_account_id: 'ACC-2002-SAV', amount_paise: 1100000, amount_cents: 1100000, currency: 'INR', memo: 'Deposit to savings', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 72 * 3600000).toISOString(), hours_ago: 72 },
  { tx_id: 'tx_hist_a4', user_id: 'USR-4401-ALICE', source_account_id: 'ACC-1001-CHK', destination_account_id: 'ACC-2002-SAV', amount_paise: 1050000, amount_cents: 1050000, currency: 'INR', memo: 'Savings allocation', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 48 * 3600000).toISOString(), hours_ago: 48 },
  { tx_id: 'tx_hist_a5', user_id: 'USR-4401-ALICE', source_account_id: 'ACC-1001-CHK', destination_account_id: 'ACC-2002-SAV', amount_paise: 900000, amount_cents: 900000, currency: 'INR', memo: 'Reserve funds transfer', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 28 * 3600000).toISOString(), hours_ago: 28 },
  { tx_id: 'tx_hist_b1', user_id: 'USR-8899-BOB', source_account_id: 'ACC-3003-BUS', destination_account_id: 'ACC-1001-CHK', amount_paise: 12000000, amount_cents: 12000000, currency: 'INR', memo: 'Commercial invoice 101', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 140 * 3600000).toISOString(), hours_ago: 140 },
  { tx_id: 'tx_hist_b2', user_id: 'USR-8899-BOB', source_account_id: 'ACC-3003-BUS', destination_account_id: 'ACC-1001-CHK', amount_paise: 15000000, amount_cents: 15000000, currency: 'INR', memo: 'Vendor payment 102', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 100 * 3600000).toISOString(), hours_ago: 100 },
  { tx_id: 'tx_hist_b3', user_id: 'USR-8899-BOB', source_account_id: 'ACC-3003-BUS', destination_account_id: 'ACC-1001-CHK', amount_paise: 13500000, amount_cents: 13500000, currency: 'INR', memo: 'Commercial operations', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 60 * 3600000).toISOString(), hours_ago: 60 },
  { tx_id: 'tx_hist_b4', user_id: 'USR-8899-BOB', source_account_id: 'ACC-3003-BUS', destination_account_id: 'ACC-1001-CHK', amount_paise: 15500000, amount_cents: 15500000, currency: 'INR', memo: 'Supplier batch payment', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 30 * 3600000).toISOString(), hours_ago: 30 },
  { tx_id: 'tx_hist_d1', user_id: 'USR-1100-DAVE', source_account_id: 'ACC-4004-CHK', destination_account_id: 'ACC-1001-CHK', amount_paise: 450000, amount_cents: 450000, currency: 'INR', memo: 'Initial test transfer', status: 'COMPLETED', created_at_utc: new Date(Date.now() - 80 * 3600000).toISOString(), hours_ago: 80 },
];

const consumedTicketsStore: Set<string> = new Set();
const dualApprovalRequestsStore: Map<string, any> = new Map();
const riskAssessmentsStore: any[] = [];

// Tamper-Evident SHA-256 Audit Chain
interface AuditEventRecord {
  event_id: string;
  prev_hash: string;
  event_type: string;
  user_id: string;
  payload: Record<string, any>;
  timestamp: string;
  event_hash: string;
}

const GENESIS_HASH = 'GENESIS_HASH_00000000000000000000000000000000000000000000000000000000';
const auditChainStore: AuditEventRecord[] = [];

function appendAuditEvent(eventType: string, userId: string, payload: Record<string, any>): AuditEventRecord {
  const clonedPayload = JSON.parse(JSON.stringify(payload || {}));
  const prevHash = auditChainStore.length === 0 ? GENESIS_HASH : auditChainStore[auditChainStore.length - 1].event_hash;
  const timestamp = new Date().toISOString();
  const event_id = 'aud_' + crypto.randomUUID().substring(0, 8);
  const content = `${prevHash}|${eventType}|${JSON.stringify(clonedPayload)}|${timestamp}`;
  const event_hash = crypto.createHash('sha256').update(content).digest('hex');

  const record: AuditEventRecord = {
    event_id,
    prev_hash: prevHash,
    event_type: eventType,
    user_id: userId,
    payload: clonedPayload,
    timestamp,
    event_hash,
  };
  auditChainStore.push(record);
  return record;
}

// Seed initial audit chain event
appendAuditEvent('SYSTEM_INITIALIZED', 'SYSTEM', { system: 'Bankism AI Security Firewall', version: '0.3.0', currency: 'INR' });

// ============================================================================
// Firewall & Security Engines
// ============================================================================
interface CanonicalTx {
  transaction_nonce: string;
  initiator_user_id: string;
  source_account_id: string;
  destination_account_id: string;
  amount_paise: number;
  amount_cents?: number;
  amount_rupees?: number;
  currency: 'INR';
}

function computeCanonicalString(tx: CanonicalTx): string {
  const amt = tx.amount_paise ?? tx.amount_cents ?? 0;
  return `${tx.transaction_nonce}|${tx.initiator_user_id}|${tx.source_account_id}|${tx.destination_account_id}|${amt}|${tx.currency || 'INR'}`;
}

function signCanonicalTx(tx: CanonicalTx): string {
  const canonical = computeCanonicalString(tx);
  return crypto.createHmac('sha256', CONFIG.HMAC_SECRET).update(canonical).digest('hex');
}

function verifyTicketSignature(ticket: any): boolean {
  if (!ticket || !ticket.signature || !ticket.canonical_tx) return false;
  if (ticket.canonical_tx.currency !== 'INR') return false;
  try {
    const expectedSig = signCanonicalTx(ticket.canonical_tx);
    const bufA = Buffer.from(ticket.signature, 'hex');
    const bufB = Buffer.from(expectedSig, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function sanitizeInput(prompt: string): string {
  let sanitized = (prompt || '').normalize('NFKC');
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u00AD\u2060-\u206F]/g, '');
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  return sanitized;
}

function maskSensitiveData(input: string): string {
  let masked = input;
  masked = masked.replace(
    /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[-\s]){3}[0-9]{4}|[0-9]{16})\b/g,
    (m) => {
      const digits = m.replace(/\D/g, '');
      return `****-****-****-${digits.slice(-4)}`;
    }
  );
  masked = masked.replace(/\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b/g, (m) => {
    const digits = m.replace(/\D/g, '');
    return `***-**-${digits.slice(-4)}`;
  });
  masked = masked.replace(/\b(bearer\s+[A-Za-z0-9\-._~+/]+=*)/gi, 'Bearer [REDACTED_TOKEN]');
  masked = masked.replace(/\b(api[_-]?key|password|secret)\s*[:=]\s*['"]?[^'"\s]+['"]?/gi, '$1: [REDACTED_SECRET]');
  return masked;
}

function evaluateFirewall(rawPrompt: string, action = 'UNSPECIFIED', amountRupees = 0, memo = '') {
  const start = performance.now();
  const sanitized = sanitizeInput(rawPrompt);
  const masked = maskSensitiveData(sanitized);

  const threats: any[] = [];
  let primaryThreat = 'NO_DETECTED_THREAT';
  let riskLevel: RiskLevel = 'LOW';
  let score = 0;

  if (!sanitized) {
    threats.push({ category: 'INVALID_INPUT', confidence: 1.0, description: 'Input consists purely of whitespace or stripped control bytes', severity: 'HIGH' });
    primaryThreat = 'INVALID_INPUT';
    riskLevel = 'HIGH';
    score = 80;
  }

  const hadInvisible = /[\u200B-\u200D\uFEFF\u00AD]/.test(rawPrompt);
  if (hadInvisible) {
    threats.push({ category: 'OBFUSCATION', confidence: 0.85, description: 'Detected invisible zero-width character evasion sequence', matched_pattern: '\\u200B zero-width bytes', severity: 'HIGH' });
    if (primaryThreat === 'NO_DETECTED_THREAT') primaryThreat = 'OBFUSCATION';
    riskLevel = 'HIGH';
    score = Math.max(score, 75);
  }

  // Strict prompt injection detection — large amounts by themselves are NOT prompt injection
  const injectionPattern = /\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands)|(system\s+override|admin\s+mode\s+enabled)\b/i;
  if (injectionPattern.test(sanitized)) {
    const matched = sanitized.match(injectionPattern)?.[0];
    threats.push({ category: 'PROMPT_INJECTION', confidence: 0.96, description: 'Instruction override attempting to disregard prior system constraints', matched_pattern: matched, severity: 'CRITICAL' });
    primaryThreat = 'PROMPT_INJECTION';
    riskLevel = 'CRITICAL';
    score = 95;
  }

  const jailbreakPattern = /\b(dan|do\s+anything\s+now|bypass\s+all\s+safety|drain\s+account|chaos\s+mode|unrestricted\s+administrator|disable\s+security)\b/i;
  if (jailbreakPattern.test(sanitized)) {
    const matched = sanitized.match(jailbreakPattern)?.[0];
    threats.push({ category: 'JAILBREAK_ATTEMPT', confidence: 0.94, description: 'Persona hijacking attempting to assume root admin privileges', matched_pattern: matched, severity: 'CRITICAL' });
    primaryThreat = 'JAILBREAK_ATTEMPT';
    riskLevel = 'CRITICAL';
    score = 98;
  }

  const sqliPattern = /('|\b)(union\s+select|select\s+.*\s+from|drop\s+table|delete\s+from|or\s+1\s*=\s*1|--|#)/i;
  if (sqliPattern.test(memo) || sqliPattern.test(sanitized)) {
    threats.push({ category: 'MALICIOUS_PAYMENT_METADATA', confidence: 0.92, description: 'Hostile SQL syntax or injection commands inside transaction metadata', matched_pattern: 'SQL injection sequence', severity: 'CRITICAL' });
    primaryThreat = 'MALICIOUS_PAYMENT_METADATA';
    riskLevel = 'CRITICAL';
    score = 90;
  }

  const violations: any[] = [];
  const reasons: string[] = [];
  let verdict: Verdict = 'APPROVE';
  let requiresStepUp = false;

  for (const t of threats) {
    if (t.severity === 'CRITICAL' || t.severity === 'HIGH') {
      verdict = 'BLOCK';
      if (t.category === 'PROMPT_INJECTION') {
        violations.push({ rule_id: 'POL-001', rule_name: 'Prompt Injection Defense', description: 'System override attempts forbidden', required_action: 'BLOCK' });
        reasons.push('POL-001 Prompt Injection attempt detected');
      } else if (t.category === 'JAILBREAK_ATTEMPT') {
        violations.push({ rule_id: 'POL-002', rule_name: 'Jailbreak Defense', description: 'Persona hijacking forbidden', required_action: 'BLOCK' });
        reasons.push('POL-002 Jailbreak attempt detected');
      } else if (t.category === 'MALICIOUS_PAYMENT_METADATA') {
        violations.push({ rule_id: 'POL-003', rule_name: 'Metadata Sanitization', description: 'SQL injection in metadata', required_action: 'BLOCK' });
        reasons.push('POL-003 Malicious SQL metadata syntax detected');
      } else if (t.category === 'OBFUSCATION') {
        violations.push({ rule_id: 'POL-004', rule_name: 'Obfuscation Defense', description: 'Zero-width characters detected', required_action: 'BLOCK' });
        reasons.push('POL-004 Character obfuscation detected');
      }
    }
  }

  // High-value policy check: If no attack detected, enters REVIEW for dual approval workflow (NEVER treated as injection)
  const highValueThresholdRupees = CONFIG.HIGH_VALUE_THRESHOLD_PAISE / 100; // ₹50,000.00
  if (verdict === 'APPROVE') {
    if (amountRupees >= highValueThresholdRupees) {
      verdict = 'REVIEW';
      requiresStepUp = true;
      violations.push({
        rule_id: 'POL-005',
        rule_name: 'High-Value Dual Approval Policy',
        description: `Transfers of ${formatINR(highValueThresholdRupees)} or more mandate secondary Risk Officer authorization`,
        required_action: 'REQUIRE_DUAL_APPROVAL',
      });
      reasons.push(`Amount (${formatINR(amountRupees)}) meets or exceeds ${formatINR(highValueThresholdRupees)} high-value policy threshold, requiring dual authorization.`);
    } else {
      reasons.push('Request passed all deterministic firewall policies.');
    }
  }

  const latency = Math.round((performance.now() - start) * 100) / 100;
  const inspection_id = 'ins_' + crypto.randomUUID().substring(0, 10);

  return {
    inspection_id,
    verdict,
    risk_level: riskLevel,
    risk_score: score,
    primary_threat: primaryThreat,
    threats_detected: threats,
    policy_violations: violations,
    sanitized_prompt: sanitized,
    masked_prompt: masked,
    requires_step_up_auth: requiresStepUp,
    execution_permitted: false, // CRITICAL INVARIANT
    reasons,
    evaluation_latency_ms: latency,
    timestamp: new Date().toISOString(),
  };
}

function computeBehavioralRisk(userId: string, srcAcc: string, dstAcc: string, amountPaise: number) {
  const completed = historicalTransactionsStore.filter((t) => t.user_id === userId && t.status === 'COMPLETED');
  const count = completed.length;
  const isColdStart = count < 3;
  const profileStatus: ProfileStatus = isColdStart ? 'INSUFFICIENT_HISTORY' : 'ESTABLISHED';

  const amounts = completed.map((t) => t.amount_paise).sort((a, b) => a - b);
  const meanPaise = count > 0 ? amounts.reduce((a, b) => a + b, 0) / count : 0;
  const variance = count > 1 ? amounts.reduce((acc, v) => acc + Math.pow(v - meanPaise, 2), 0) / (count - 1) : 0;
  const stdPaise = Math.sqrt(variance);
  const knownRecipients = new Set(completed.map((t) => t.destination_account_id));

  const factorScores: { name: string; category: string; score: number }[] = [];

  if (!isColdStart && meanPaise > 0) {
    const ratio = amountPaise / meanPaise;
    const zScore = stdPaise > 0 ? (amountPaise - meanPaise) / stdPaise : (ratio - 1) * 2;
    if (zScore >= 2.5 || ratio >= 3.0) {
      const score = Math.min(90, Math.round((40 + ratio * 10 + Math.max(0, zScore) * 8) * 10) / 10);
      factorScores.push({ name: 'AMOUNT_SPIKE_ANOMALY', category: 'AMOUNT', score });
    }
  }

  const count1h = completed.filter((t) => t.hours_ago <= 1).length;
  if (count1h >= 3) {
    const vScore = Math.min(85, 45 + count1h * 10);
    factorScores.push({ name: 'RAPID_VELOCITY_BURST_1H', category: 'VELOCITY', score: vScore });
  }

  if (!knownRecipients.has(dstAcc)) {
    if (!isColdStart) {
      factorScores.push({ name: 'NOVEL_COUNTERPARTY', category: 'COUNTERPARTY', score: 35.0 });
    } else {
      factorScores.push({ name: 'INITIAL_COUNTERPARTY', category: 'COUNTERPARTY', score: 5.0 });
    }
  }

  const failed24h = historicalTransactionsStore.filter((t) => t.user_id === userId && t.status !== 'COMPLETED' && t.hours_ago <= 24).length;
  if (failed24h >= 3) {
    const fScore = Math.min(75, 35 + failed24h * 10);
    factorScores.push({ name: 'REPEATED_FAILED_ATTEMPTS', category: 'ATTEMPTS', score: fScore });
  }

  const categoryMax = new Map<string, { name: string; score: number }>();
  for (const f of factorScores) {
    const curr = categoryMax.get(f.category);
    if (!curr || f.score > curr.score) {
      categoryMax.set(f.category, { name: f.name, score: f.score });
    }
  }

  const sortedCatScores = Array.from(categoryMax.values()).sort((a, b) => b.score - a.score);
  let composite = 5.0;
  if (sortedCatScores.length > 0) {
    const primary = sortedCatScores[0].score;
    const secondarySum = sortedCatScores.slice(1).reduce((acc, f) => acc + f.score, 0);
    const sigCount = sortedCatScores.filter((f) => f.score >= 20).length;
    const convergenceBonus = sigCount >= 2 ? (sigCount >= 3 ? 15.0 : 8.0) : 0.0;
    composite = Math.min(98.0, Math.round((primary + secondarySum * 0.25 + convergenceBonus) * 10) / 10);
  }

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

  const watermark = `wm_count${completed.length}_head${auditChainStore.length > 0 ? auditChainStore[auditChainStore.length - 1].event_hash.slice(0, 10) : '0'}`;

  return {
    score: composite,
    level,
    profileStatus,
    policyAction,
    factors: sortedCatScores.map((s) => s.name),
    historyWatermark: watermark,
  };
}

// ============================================================================
// API Endpoints
// ============================================================================

// 1. Health Subsystem Check
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    subsystems: {
      firewall: 'active',
      database: 'connected',
      risk_engine: 'active',
      audit_chain: 'active',
      executor: 'active',
    },
    environment: 'production',
    policy_version: '0.3.0',
    currency: 'INR',
    database_records: { accounts: accountsStore.size },
  });
});

// 2. Firewall Inspection
app.post('/firewall/inspect', (req: Request, res: Response) => {
  const { prompt, action, amount, memo } = req.body || {};
  const amountRupees = Number(amount) || 0;
  const result = evaluateFirewall(prompt || '', action, amountRupees, memo || '');
  appendAuditEvent('FIREWALL_INSPECTION', 'ANONYMOUS', {
    inspection_id: result.inspection_id,
    verdict: result.verdict,
    primary_threat: result.primary_threat,
    risk_level: result.risk_level,
    amount_rupees: amountRupees,
    currency: 'INR',
  });
  res.json(result);
});

// 3. User Accounts Listing
app.get('/banking/accounts', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const userAccounts: any[] = [];
    for (const [id, acc] of accountsStore.entries()) {
      if (acc.owner_user_id === principal.user_id) {
        userAccounts.push({
          account_id: acc.account_id,
          name: acc.name,
          owner: principal.username,
          balance_rupees: acc.balance_paise / 100,
          balance_paise: acc.balance_paise,
          daily_limit_rupees: acc.daily_limit_paise / 100,
          daily_limit_paise: acc.daily_limit_paise,
          currency: 'INR',
          // Backward-compatibility aliases
          balance_dollars: acc.balance_paise / 100,
          balance_cents: acc.balance_paise,
          daily_limit_dollars: acc.daily_limit_paise / 100,
        });
      }
    }
    res.json(userAccounts);
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 4. Prepare Transfer
app.post('/banking/transfers/prepare', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const { source_account_id, destination_account_id, amount, prompt, memo } = req.body || {};
    const amountRupees = Number(amount) || 0;
    const amountPaise = Math.round(amountRupees * 100);

    if (amountPaise <= 0) {
      return res.status(400).json({ detail: 'AMOUNT_INVALID: Amount must be greater than zero.' });
    }

    // 1. Ownership check (Fail-closed)
    const src = accountsStore.get(source_account_id);
    if (!src || src.owner_user_id !== principal.user_id) {
      return res.status(403).json({ detail: `ACCOUNT_ACCESS_DENIED: User '${principal.username}' does not own '${source_account_id}'.` });
    }

    // 2. Destination account check
    if (!destination_account_id || typeof destination_account_id !== 'string') {
      return res.status(400).json({ detail: 'RECIPIENT_INVALID: Destination account identifier is required.' });
    }
    if (source_account_id === destination_account_id) {
      return res.status(400).json({ detail: 'RECIPIENT_INVALID: Source and destination accounts cannot be identical.' });
    }

    // 3. Balance check (Fail-closed)
    if (src.balance_paise < amountPaise) {
      return res.status(400).json({
        detail: `INSUFFICIENT_FUNDS: Available ${formatINR(src.balance_paise / 100)}, requested ${formatINR(amountRupees)}.`,
      });
    }

    // 4. Daily transaction limit check (Fail-closed)
    if (src.daily_limit_paise && amountPaise > src.daily_limit_paise) {
      return res.status(400).json({
        detail: `DAILY_LIMIT_EXCEEDED: Requested ${formatINR(amountRupees)} exceeds account daily limit of ${formatINR(src.daily_limit_paise / 100)}.`,
      });
    }

    // 5. Run Firewall Check (Deterministic inspection)
    const fw = evaluateFirewall(prompt || 'Transfer funds', 'TRANSFER_FUNDS', amountRupees, memo || '');
    if (fw.verdict === 'BLOCK') {
      appendAuditEvent('TRANSFER_BLOCKED_FIREWALL', principal.user_id, {
        source_account_id,
        destination_account_id,
        amount_paise: amountPaise,
        amount_rupees: amountRupees,
        currency: 'INR',
        threat: fw.primary_threat,
        reasons: fw.reasons,
      });
      return res.status(400).json({ detail: `FIREWALL_BLOCK: ${fw.reasons.join(', ')}` });
    }

    // 6. Behavioral Risk Assessment in minor units (paise)
    const risk = computeBehavioralRisk(principal.user_id, source_account_id, destination_account_id, amountPaise);
    const assessment_id = 'asm_' + crypto.randomUUID().substring(0, 10);
    const riskRecord = {
      assessment_id,
      user_id: principal.user_id,
      source_account_id,
      destination_account_id,
      amount_paise: amountPaise,
      amount_rupees: amountRupees,
      amount_cents: amountPaise,
      currency: 'INR',
      risk_score: risk.score,
      risk_level: risk.level,
      profile_status: risk.profileStatus,
      policy_action: risk.policyAction,
      factors_json: JSON.stringify(risk.factors),
      history_watermark: risk.historyWatermark,
      created_at_utc: new Date().toISOString(),
    };
    riskAssessmentsStore.unshift(riskRecord);

    const highValueThresholdRupees = CONFIG.HIGH_VALUE_THRESHOLD_PAISE / 100;
    const isHighValue = amountRupees >= highValueThresholdRupees;
    const isHighRisk = risk.level === 'HIGH' || risk.level === 'CRITICAL';
    const isFirewallReview = fw.verdict === 'REVIEW';
    const requiresDualApproval = isHighValue || isHighRisk || isFirewallReview;

    if (requiresDualApproval) {
      const requestId = 'req_' + crypto.randomUUID().substring(0, 10);
      const reasonText = isHighValue
        ? `High-value transfer (${formatINR(amountRupees)}) meets or exceeds ${formatINR(highValueThresholdRupees)} policy threshold, requiring dual authorization.`
        : `Behavioral risk elevated (${risk.level}): ${risk.policyAction}`;

      const reqRecord = {
        request_id: requestId,
        initiator_user_id: principal.user_id,
        source_account_id,
        destination_account_id,
        amount_paise: amountPaise,
        amount_rupees: amountRupees,
        amount_cents: amountPaise,
        currency: 'INR',
        reason: reasonText,
        status: 'PENDING',
        created_at_utc: new Date().toISOString(),
        expires_at_utc: new Date(Date.now() + CONFIG.DUAL_APPROVAL_EXPIRY_SECONDS * 1000).toISOString(),
      };
      dualApprovalRequestsStore.set(requestId, reqRecord);
      appendAuditEvent('DUAL_APPROVAL_REQUESTED', principal.user_id, reqRecord);

      return res.json({
        status: 'PENDING_DUAL_APPROVAL',
        ticket: null,
        dual_approval_request: reqRecord,
        risk_assessment: riskRecord,
        reasons: [reasonText],
      });
    }

    // 7. Single Authorized Ticket Generation (Only when all policy conditions are fully satisfied)
    const ticketId = 'tkt_' + crypto.randomUUID().substring(0, 10);
    const canonicalTx: CanonicalTx = {
      transaction_nonce: crypto.randomUUID(),
      initiator_user_id: principal.user_id,
      source_account_id,
      destination_account_id,
      amount_paise: amountPaise,
      amount_cents: amountPaise,
      amount_rupees: amountRupees,
      currency: 'INR',
    };
    const signature = signCanonicalTx(canonicalTx);
    const ticket = {
      ticket_id: ticketId,
      fingerprint: crypto.createHash('sha256').update(JSON.stringify(canonicalTx)).digest('hex'),
      history_watermark: risk.historyWatermark,
      canonical_tx: canonicalTx,
      expires_at: Math.floor(Date.now() / 1000) + CONFIG.TICKET_EXPIRY_SECONDS,
      signature,
    };

    appendAuditEvent('AUTHORIZATION_TICKET_ISSUED', principal.user_id, { ticket_id: ticketId, canonical_tx: canonicalTx });

    res.json({
      status: 'AUTHORIZED',
      ticket,
      dual_approval_request: null,
      risk_assessment: riskRecord,
      reasons: ['Authorized under baseline policy'],
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 5. Confirm & Execute Transfer
app.post('/banking/transfers/confirm', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const { ticket } = req.body || {};

    if (!ticket) {
      return res.status(400).json({ detail: 'TICKET_MISSING: Authorization ticket is required.' });
    }

    if (!ticket.canonical_tx) {
      return res.status(400).json({ detail: 'TICKET_INVALID: Canonical transaction payload missing.' });
    }

    if (ticket.canonical_tx.initiator_user_id !== principal.user_id) {
      return res.status(403).json({ detail: 'PRINCIPAL_MISMATCH: Ticket does not belong to caller.' });
    }

    if (ticket.canonical_tx.currency !== 'INR') {
      return res.status(400).json({ detail: `CURRENCY_INVALID: Only INR transactions permitted. Ticket had '${ticket.canonical_tx.currency}'.` });
    }

    if (consumedTicketsStore.has(ticket.ticket_id)) {
      return res.status(409).json({ detail: 'TICKET_CONSUMED: Replay attack prevented. Ticket already used.' });
    }

    if (ticket.expires_at < Math.floor(Date.now() / 1000)) {
      return res.status(400).json({ detail: 'TICKET_EXPIRED: Ticket timestamp is expired.' });
    }

    if (!verifyTicketSignature(ticket)) {
      return res.status(401).json({ detail: 'SIGNATURE_INVALID: Ticket signature forged or tampered.' });
    }

    const { source_account_id, destination_account_id } = ticket.canonical_tx;
    const amountPaise = ticket.canonical_tx.amount_paise ?? ticket.canonical_tx.amount_cents;
    const src = accountsStore.get(source_account_id);
    if (!src || src.balance_paise < amountPaise) {
      return res.status(400).json({ detail: 'INSUFFICIENT_FUNDS: Balances altered since prepare phase.' });
    }

    // Atomic debit & credit in minor units (paise)
    src.balance_paise -= amountPaise;
    src.balance_cents = src.balance_paise;
    const dst = accountsStore.get(destination_account_id);
    if (dst) {
      dst.balance_paise += amountPaise;
      dst.balance_cents = dst.balance_paise;
    }

    consumedTicketsStore.add(ticket.ticket_id);

    const txId = 'TXN-' + crypto.randomUUID().substring(0, 8).toUpperCase();
    const auditRecord = appendAuditEvent('TRANSFER_EXECUTED', principal.user_id, {
      tx_id: txId,
      source_account_id,
      destination_account_id,
      amount_paise: amountPaise,
      amount_rupees: amountPaise / 100,
      currency: 'INR',
      ticket_id: ticket.ticket_id,
    });

    const historicalRecord: HistoricalTransaction = {
      tx_id: txId,
      user_id: principal.user_id,
      source_account_id,
      destination_account_id,
      amount_paise: amountPaise,
      amount_cents: amountPaise,
      currency: 'INR',
      memo: 'Transferred via Bankism Authorization Gateway',
      status: 'COMPLETED',
      created_at_utc: new Date().toISOString(),
      hours_ago: 0,
      audit_event_hash: auditRecord.event_hash,
    };
    historicalTransactionsStore.unshift(historicalRecord);

    res.json({
      status: 'COMPLETED',
      receipt: {
        tx_id: txId,
        source_account_id,
        destination_account_id,
        amount_rupees: amountPaise / 100,
        amount_paise: amountPaise,
        currency: 'INR',
        amount_dollars: amountPaise / 100,
        amount_cents: amountPaise,
        status: 'COMPLETED',
        audit_event_hash: auditRecord.event_hash,
        executed_at: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 6. Dual Approval Review & Sign-Off
app.post('/banking/transfers/approve', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const { request_id, approved, reason } = req.body || {};

    const approvalReq = dualApprovalRequestsStore.get(request_id);
    if (!approvalReq) {
      return res.status(404).json({ detail: `REQUEST_NOT_FOUND: Request '${request_id}' not found.` });
    }

    // Separation of Duties check (Initiator cannot approve their own transfer)
    if (approvalReq.initiator_user_id === principal.user_id) {
      return res.status(403).json({ detail: 'SEPARATION_OF_DUTIES_VIOLATION: Approver cannot be the transaction initiator.' });
    }

    if (principal.role !== 'APPROVER') {
      return res.status(403).json({ detail: 'ROLE_UNAUTHORIZED: Dual approval requires APPROVER role.' });
    }

    if (!approved) {
      approvalReq.status = 'REJECTED';
      appendAuditEvent('DUAL_APPROVAL_REJECTED', principal.user_id, { request_id, reason, currency: 'INR' });
      return res.json({ status: 'REJECTED', request_id, approver: principal.username, ticket: null });
    }

    approvalReq.status = 'APPROVED';
    approvalReq.approver_user_id = principal.user_id;

    // Issue executable HMAC ticket upon verified approval
    const ticketId = 'tkt_dual_' + crypto.randomUUID().substring(0, 10);
    const amountPaise = approvalReq.amount_paise ?? approvalReq.amount_cents;
    const canonicalTx: CanonicalTx = {
      transaction_nonce: crypto.randomUUID(),
      initiator_user_id: approvalReq.initiator_user_id,
      source_account_id: approvalReq.source_account_id,
      destination_account_id: approvalReq.destination_account_id,
      amount_paise: amountPaise,
      amount_cents: amountPaise,
      amount_rupees: amountPaise / 100,
      currency: 'INR',
    };
    const signature = signCanonicalTx(canonicalTx);
    const ticket = {
      ticket_id: ticketId,
      fingerprint: crypto.createHash('sha256').update(JSON.stringify(canonicalTx)).digest('hex'),
      history_watermark: 'wm_dual_approved',
      canonical_tx: canonicalTx,
      expires_at: Math.floor(Date.now() / 1000) + CONFIG.TICKET_EXPIRY_SECONDS,
      signature,
    };

    appendAuditEvent('DUAL_APPROVAL_APPROVED', principal.user_id, { request_id, ticket_id: ticketId, currency: 'INR' });

    res.json({
      status: 'APPROVED',
      request_id,
      approver: principal.username,
      ticket,
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 7. User Risk Profile
app.get('/banking/risk/profile', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const userTxs = historicalTransactionsStore.filter((t) => t.user_id === principal.user_id && t.status === 'COMPLETED');
    const amountsRupees = userTxs.map((t) => t.amount_paise / 100);
    const mean = amountsRupees.length > 0 ? amountsRupees.reduce((a, b) => a + b, 0) / amountsRupees.length : 0;
    const std = amountsRupees.length > 1 ? Math.sqrt(amountsRupees.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / (amountsRupees.length - 1)) : 0;
    const knownCounterparties = Array.from(new Set(userTxs.map((t) => t.destination_account_id)));

    res.json({
      user_id: principal.user_id,
      username: principal.username,
      role: principal.role,
      profile_status: userTxs.length >= 3 ? 'ESTABLISHED' : 'INSUFFICIENT_HISTORY',
      transaction_count: userTxs.length,
      currency: 'INR',
      count_1h: userTxs.filter((t) => t.hours_ago <= 1).length,
      count_24h: userTxs.filter((t) => t.hours_ago <= 24).length,
      failed_24h: historicalTransactionsStore.filter((t) => t.user_id === principal.user_id && t.status !== 'COMPLETED' && t.hours_ago <= 24).length,
      mean_rupees: Math.round(mean * 100) / 100,
      median_rupees: Math.round(mean * 100) / 100,
      std_rupees: Math.round(std * 100) / 100,
      max_rupees: amountsRupees.length > 0 ? Math.max(...amountsRupees) : 0,
      // Backward compatibility
      mean_dollars: Math.round(mean * 100) / 100,
      median_dollars: Math.round(mean * 100) / 100,
      std_dollars: Math.round(std * 100) / 100,
      max_dollars: amountsRupees.length > 0 ? Math.max(...amountsRupees) : 0,
      known_counterparties: knownCounterparties,
      history_watermark: `wm_count${userTxs.length}`,
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 8. User Risk Assessments
app.get('/banking/risk/assessments', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const assessments = riskAssessmentsStore
      .filter((r) => r.user_id === principal.user_id)
      .map((r) => ({
        ...r,
        username: principal.username,
        transaction_fingerprint: '',
        confidence: 0.85,
        risk_factors: JSON.parse(r.factors_json || '[]'),
        explanations: JSON.parse(r.factors_json || '[]'),
        recommended_action_reason: 'Persisted risk assessment',
        model_version: '0.3.0',
        assessed_at: r.created_at_utc,
        final_outcome: 'COMPLETED',
        firewall_verdict: 'APPROVE',
      }));
    res.json(assessments);
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 9. Single Risk Assessment
app.get('/banking/risk/assessments/:assessment_id', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const assessment = riskAssessmentsStore.find((r) => r.assessment_id === req.params.assessment_id);
    if (!assessment) {
      return res.status(404).json({ detail: 'ASSESSMENT_NOT_FOUND' });
    }
    if (assessment.user_id !== principal.user_id && principal.role !== 'APPROVER') {
      return res.status(403).json({ detail: 'ACCESS_DENIED' });
    }
    res.json({
      ...assessment,
      username: principal.username,
      transaction_fingerprint: '',
      confidence: 0.85,
      risk_factors: JSON.parse(assessment.factors_json || '[]'),
      explanations: JSON.parse(assessment.factors_json || '[]'),
      recommended_action_reason: 'Persisted risk assessment',
      model_version: '0.3.0',
      assessed_at: assessment.created_at_utc,
      final_outcome: 'COMPLETED',
      firewall_verdict: 'APPROVE',
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Internal error' });
  }
});

// 10. Audit Chain Cryptographic Verification
app.get('/banking/audit/verify', (req: Request, res: Response) => {
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < auditChainStore.length; i++) {
    const item = auditChainStore[i];
    if (item.prev_hash !== prevHash) {
      return res.json({
        valid: false,
        total_events: auditChainStore.length,
        head_hash: auditChainStore[auditChainStore.length - 1]?.event_hash || '',
        broken_at_index: i,
        details: `Broken prev_hash chain link at index ${i}`,
      });
    }
    const content = `${item.prev_hash}|${item.event_type}|${JSON.stringify(item.payload)}|${item.timestamp}`;
    const computed = crypto.createHash('sha256').update(content).digest('hex');
    if (item.event_hash !== computed) {
      return res.json({
        valid: false,
        total_events: auditChainStore.length,
        head_hash: auditChainStore[auditChainStore.length - 1]?.event_hash || '',
        broken_at_index: i,
        details: `Tampered payload hash at index ${i}`,
      });
    }
    prevHash = item.event_hash;
  }

  res.json({
    valid: true,
    total_events: auditChainStore.length,
    head_hash: auditChainStore.length > 0 ? auditChainStore[auditChainStore.length - 1].event_hash : GENESIS_HASH,
    broken_at_index: null,
    details: `All ${auditChainStore.length} cryptographically chained events verified unbroken.`,
  });
});

// 11. Security Operations / Sentinel Audit Events with Filtering & Summary
app.get('/banking/audit/events', (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const offset = Number(req.query.offset) || 0;
    const filter = ((req.query.filter as string) || 'all').toLowerCase();

    // Calculate summary metrics across all events
    let totalInspections = 0;
    let blockedCount = 0;
    let reviewCount = 0;
    let completedCount = 0;

    for (const evt of auditChainStore) {
      if (evt.event_type === 'FIREWALL_INSPECTION') {
        totalInspections++;
        if (evt.payload.verdict === 'BLOCK') blockedCount++;
        else if (evt.payload.verdict === 'REVIEW') reviewCount++;
      } else if (evt.event_type === 'TRANSFER_BLOCKED_FIREWALL') {
        blockedCount++;
      } else if (evt.event_type === 'DUAL_APPROVAL_REQUESTED') {
        reviewCount++;
      } else if (evt.event_type === 'TRANSFER_EXECUTED') {
        completedCount++;
      }
    }

    let filtered = [...auditChainStore].reverse(); // Newest first

    if (filter === 'blocked') {
      filtered = filtered.filter(
        (e) => e.event_type === 'TRANSFER_BLOCKED_FIREWALL' || (e.event_type === 'FIREWALL_INSPECTION' && e.payload.verdict === 'BLOCK')
      );
    } else if (filter === 'review') {
      filtered = filtered.filter(
        (e) => e.event_type === 'DUAL_APPROVAL_REQUESTED' || (e.event_type === 'FIREWALL_INSPECTION' && e.payload.verdict === 'REVIEW')
      );
    } else if (filter === 'completed') {
      filtered = filtered.filter((e) => e.event_type === 'TRANSFER_EXECUTED');
    } else if (filter === 'inspection') {
      filtered = filtered.filter((e) => e.event_type === 'FIREWALL_INSPECTION');
    }

    const paged = filtered.slice(offset, offset + limit);

    res.json({
      total: filtered.length,
      limit,
      offset,
      events: paged,
      summary: {
        total_events: auditChainStore.length,
        total_inspections: totalInspections,
        blocked_count: blockedCount,
        review_count: reviewCount,
        completed_count: completedCount,
        head_hash: auditChainStore.length > 0 ? auditChainStore[auditChainStore.length - 1].event_hash : GENESIS_HASH,
      },
    });
  } catch (err: any) {
    res.status(500).json({ detail: err.message || 'Failed to fetch audit events' });
  }
});

// 12. Pending Dual Approval Requests for Risk Officers
app.get('/banking/transfers/pending', (req: Request, res: Response) => {
  try {
    const list: any[] = [];
    for (const [id, reqRecord] of dualApprovalRequestsStore.entries()) {
      if (reqRecord.status === 'PENDING') {
        list.push(reqRecord);
      }
    }
    res.json(list);
  } catch (err: any) {
    res.status(500).json({ detail: err.message || 'Failed to fetch pending approvals' });
  }
});

// 13. Customer Conversational AI Assistant (Natural Language Banking Interface)
// Interprets customer queries, explains balances and policies in INR, and structures transfer proposals for explicit confirmation.
// Never directly mutates the ledger or authorizes transfers.
app.post('/banking/chat', (req: Request, res: Response) => {
  try {
    const principal = resolvePrincipal(req);
    const { message, account_id } = req.body || {};
    const text = (message || '').trim();

    if (!text) {
      return res.status(400).json({ detail: 'MESSAGE_REQUIRED: Chat message cannot be empty.' });
    }

    // Get principal's current accounts
    const userAccs = Array.from(accountsStore.values()).filter((a) => a.owner_user_id === principal.user_id);
    const defaultAcc = userAccs.find((a) => a.account_id === account_id) || userAccs[0];

    const lower = text.toLowerCase();

    // 1. Balance inquiry
    if (
      lower.includes('balance') ||
      lower.includes('how much') ||
      lower.includes('account status') ||
      lower.includes('what do i have')
    ) {
      const breakdown = userAccs
        .map((a) => `${a.name} (${a.account_id}): ${formatINR(a.balance_paise / 100)} [Daily limit: ${formatINR(a.daily_limit_paise / 100)}]`)
        .join('\n');
      return res.json({
        intent: 'READ_BALANCE',
        reply: `Here is the current verified balance for your account(s):\n\n${breakdown}\n\nAll funds are simulated sandbox ledger balances denominated in Indian Rupees (INR).`,
        proposal: null,
        engine: 'deterministic-rules',
      });
    }

    // 2. Recent transactions inquiry
    if (
      lower.includes('recent transaction') ||
      lower.includes('history') ||
      lower.includes('statement') ||
      lower.includes('show my transfer') ||
      lower.includes('show recent')
    ) {
      const userTxs = historicalTransactionsStore
        .filter((t) => t.user_id === principal.user_id && t.status === 'COMPLETED')
        .slice(0, 5);
      if (userTxs.length === 0) {
        return res.json({
          intent: 'READ_TRANSACTIONS',
          reply: `You currently have no completed transactions on record. Your accounts are ready for transfers.`,
          proposal: null,
          engine: 'deterministic-rules',
        });
      }
      const list = userTxs
        .map(
          (t) =>
            `• ${t.tx_id}: ${formatINR(t.amount_paise / 100)} from ${t.source_account_id} to ${t.destination_account_id} ("${t.memo || 'Transfer'}")`
        )
        .join('\n');
      return res.json({
        intent: 'READ_TRANSACTIONS',
        reply: `Here are your recent completed transactions:\n\n${list}\n\nEach completed transaction is cryptographically chained in our SHA-256 tamper-evident audit ledger in INR.`,
        proposal: null,
        engine: 'deterministic-rules',
      });
    }

    // 3. "Why was my transaction blocked?" inquiry
    if (
      lower.includes('why was') ||
      lower.includes('why blocked') ||
      lower.includes('blocked transaction') ||
      lower.includes('why did it fail') ||
      lower.includes('firewall policy')
    ) {
      return res.json({
        intent: 'EXPLAIN_POLICY',
        reply: `Bankism protects your account with a deterministic AI security firewall and multi-layer policies:\n\n1. **POL-001 (Prompt Injection)**: Blocks attempts to override system commands, bypass controls, or disregard instructions.\n2. **POL-002 (Jailbreak Defense)**: Blocks persona hijacking (e.g., claiming to be an administrator or unrestricted persona).\n3. **POL-003 (Metadata Sanitization)**: Blocks hostile SQL injection syntax or scripts inside transfer memos.\n4. **POL-004 (Obfuscation Defense)**: Strips zero-width and invisible evasive characters.\n5. **POL-005 (High-Value Dual Approval)**: Transfers of ₹50,000.00 or more or with elevated behavioral risk require secondary sign-off from an authorized Risk Officer before funds can be debited.\n6. **Ownership & Balance Invariants**: You can only transfer funds from accounts you legitimately own, within verified balance and daily limits.`,
        proposal: null,
        engine: 'deterministic-rules',
      });
    }

    // 4. Transfer intent detection (transfer, send, pay, wire)
    const isTransferIntent =
      lower.includes('transfer') ||
      lower.includes('send') ||
      lower.includes('pay') ||
      lower.includes('wire') ||
      lower.includes('give') ||
      lower.includes('ignore all previous') || // Hostile request pretending to be transfer
      lower.includes('system override');

    if (isTransferIntent) {
      // Parse amount supporting ₹, $, or plain numbers with Indian grouping
      let amount = 5000.0; // default ₹5,000.00
      const amountMatch = text.match(/(?:₹|\$|rs\.?|inr)?\s*([0-9]{1,3}(?:,[0-9]{2})*(?:,[0-9]{3})(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)/i);
      if (amountMatch) {
        amount = parseFloat(amountMatch[1].replace(/,/g, ''));
      }

      // Parse recipient / destination
      let destAccount = 'ACC-2002-SAV'; // Default savings
      if (lower.includes('acc-3003-bus') || lower.includes('bob') || lower.includes('vendor') || lower.includes('supplier')) {
        destAccount = 'ACC-3003-BUS';
      } else if (lower.includes('acc-9999-evil') || lower.includes('evil') || lower.includes('hacker')) {
        destAccount = 'ACC-9999-EVIL';
      } else if (lower.includes('acc-4004-chk') || lower.includes('dave')) {
        destAccount = 'ACC-4004-CHK';
      } else if (lower.includes('acc-1001-chk') || lower.includes('checking')) {
        destAccount = 'ACC-1001-CHK';
      } else if (lower.includes('savings') || lower.includes('acc-2002-sav')) {
        destAccount = 'ACC-2002-SAV';
      }

      // Determine source account (from user's owned accounts)
      let srcAccount = defaultAcc ? defaultAcc.account_id : 'ACC-1001-CHK';
      if (lower.includes('from acc-2002-sav') || lower.includes('from savings')) {
        srcAccount = 'ACC-2002-SAV';
      } else if (lower.includes('from acc-3003-bus')) {
        srcAccount = 'ACC-3003-BUS';
      } else if (lower.includes('from acc-1001-chk') || lower.includes('from checking')) {
        srcAccount = 'ACC-1001-CHK';
      }

      // Extract or synthesize memo
      let memo = 'Transfer initiated via Bankism AI';
      if (lower.includes('for ')) {
        const forIndex = text.toLowerCase().indexOf('for ');
        memo = text.substring(forIndex + 4).trim();
      } else if (lower.includes('lunch')) {
        memo = 'Lunch payment';
      } else if (lower.includes('savings')) {
        memo = 'Monthly routine savings';
      }

      // Return structured proposal for user confirmation in INR
      return res.json({
        intent: 'TRANSFER_PROPOSAL',
        reply: `I have prepared a transfer proposal for ${formatINR(amount)} to ${destAccount}. Please review the details below. To protect your funds, you must explicitly confirm this transaction, and it will be evaluated by our security firewall before authorization.`,
        proposal: {
          source_account_id: srcAccount,
          destination_account_id: destAccount,
          amount,
          currency: 'INR',
          memo,
          raw_prompt: text,
        },
        engine: 'deterministic-rules',
      });
    }

    // Default conversational response
    return res.json({
      intent: 'GENERAL_ASSISTANCE',
      reply: `Hello ${principal.username}! I am Bankism AI, your intelligent banking assistant. How can I help you today? You can ask:\n• "What is my available balance?"\n• "Show my recent transactions."\n• "Transfer ₹5,000 to savings for routine allocation."\n• "Transfer ₹1,50,000 to ACC-3003-BUS for equipment lease."\n• "Why was my transaction blocked?"`,
      proposal: null,
      engine: 'deterministic-rules',
    });
  } catch (err: any) {
    res.status(err.status || 500).json({ detail: err.message || 'Chat service error' });
  }
});

// ============================================================================
// Vite Middleware / Static Serving
// ============================================================================
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bankism] Full-Stack Server active on http://0.0.0.0:${PORT} (INR default)`);
  });
}

startServer().catch((err) => {
  console.error('[Bankism] Failed to start server:', err);
  process.exit(1);
});
