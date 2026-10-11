/**
 * @file api.ts
 * @description Typed API client for Bankism FastAPI backend with graceful fallback.
 */

export const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8000';

export interface ApiInspectResponse {
  inspection_id: string;
  verdict: 'APPROVE' | 'BLOCK' | 'REVIEW';
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  primary_threat: string;
  threats_detected: Array<{
    category: string;
    confidence: number;
    description: string;
    matched_pattern?: string;
    severity: string;
  }>;
  policy_violations: Array<{
    rule_id: string;
    rule_name: string;
    description: string;
    required_action: string;
  }>;
  sanitized_prompt: string;
  masked_prompt: string;
  requires_step_up_auth: boolean;
  execution_permitted: boolean;
  reasons: string[];
  evaluation_latency_ms: number;
  timestamp: string;
}

export interface ApiAccountInfo {
  account_id: string;
  name: string;
  owner: string;
  balance_dollars: number;
  balance_cents: number;
  daily_limit_dollars: number;
}

export interface ApiPrepareResponse {
  status: 'AUTHORIZED' | 'PENDING_DUAL_APPROVAL';
  ticket: any | null;
  dual_approval_request: any | null;
  risk_assessment: any;
  reasons: string[];
}

export async function checkBackendHealth(): Promise<boolean> {
  if (typeof window !== 'undefined' && window.location.protocol === 'https:' && (!API_BASE_URL || API_BASE_URL.startsWith('http://localhost'))) {
    // Avoid blocked mixed-content calls in HTTPS cloud preview environments
    return false;
  }
  try {
    const res = await fetch(`${API_BASE_URL}/health`, { method: 'GET', signal: AbortSignal.timeout(2000) });
    if (!res.ok) return false;
    const data = await res.json().catch(() => null);
    return data && (data.status === 'healthy' || data.status === 'ok');
  } catch {
    return false;
  }
}

export async function inspectPromptApi(prompt: string, action = 'UNSPECIFIED', amount?: number, memo?: string): Promise<ApiInspectResponse> {
  const res = await fetch(`${API_BASE_URL}/firewall/inspect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, action, amount, memo }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Inspection failed' }));
    throw new Error(err.detail || 'Inspection failed');
  }
  return res.json();
}

export async function fetchAccountsApi(username: string): Promise<ApiAccountInfo[]> {
  const res = await fetch(`${API_BASE_URL}/banking/accounts`, {
    method: 'GET',
    headers: { 'X-Bankism-Mock-User': username },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch accounts' }));
    throw new Error(err.detail || 'Failed to fetch accounts');
  }
  return res.json();
}

export async function prepareTransferApi(
  username: string,
  source_account_id: string,
  destination_account_id: string,
  amount: number,
  prompt?: string,
  memo?: string
): Promise<ApiPrepareResponse> {
  const res = await fetch(`${API_BASE_URL}/banking/transfers/prepare`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bankism-Mock-User': username,
    },
    body: JSON.stringify({
      source_account_id,
      destination_account_id,
      amount,
      prompt,
      memo,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Transfer preparation rejected' }));
    throw new Error(err.detail || 'Transfer preparation rejected');
  }
  return res.json();
}

export async function confirmTransferApi(username: string, ticket: any): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/banking/transfers/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bankism-Mock-User': username,
    },
    body: JSON.stringify({ ticket }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Transfer confirmation rejected' }));
    throw new Error(err.detail || 'Transfer confirmation rejected');
  }
  return res.json();
}

export async function approveTransferApi(username: string, request_id: string, approved: boolean, reason?: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/banking/transfers/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bankism-Mock-User': username,
    },
    body: JSON.stringify({ request_id, approved, reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Approval rejected' }));
    throw new Error(err.detail || 'Approval rejected');
  }
  return res.json();
}

export async function verifyAuditChainApi(): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/banking/audit/verify`, {
    method: 'GET',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Audit verification failed' }));
    throw new Error(err.detail || 'Audit verification failed');
  }
  return res.json();
}

export async function fetchRiskProfileApi(username: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/banking/risk/profile`, {
    method: 'GET',
    headers: { 'X-Bankism-Mock-User': username },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch risk profile' }));
    throw new Error(err.detail || 'Failed to fetch risk profile');
  }
  return res.json();
}

export async function fetchRiskAssessmentsApi(username: string): Promise<any[]> {
  const res = await fetch(`${API_BASE_URL}/banking/risk/assessments`, {
    method: 'GET',
    headers: { 'X-Bankism-Mock-User': username },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch risk assessments' }));
    throw new Error(err.detail || 'Failed to fetch risk assessments');
  }
  return res.json();
}

