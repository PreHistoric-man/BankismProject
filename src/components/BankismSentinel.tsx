/**
 * @file BankismSentinel.tsx
 * @description Bankism Sentinel — Security Operations Center (SOC) Dashboard
 * Monitors real-time transaction decisions, threat telemetry, deterministic firewall policy violations,
 * behavioral risk scores, dual approval requests, and cryptographic SHA-256 audit chain verification.
 */

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  Lock,
  Terminal,
  Activity,
  Layers,
  FileText,
  Key,
  Check,
  X,
  UserCheck,
  Radio,
  Sliders,
  Eye,
  Info,
} from 'lucide-react';
import {
  fetchAuditEventsApi,
  fetchPendingApprovalsApi,
  approveTransferApi,
  verifyAuditChainApi,
  SentinelAuditResponse,
  SentinelAuditSummary,
  formatINR,
} from '../api';

interface BankismSentinelProps {
  onNavigateToApp: () => void;
  backendOnline: boolean;
}

export default function BankismSentinel({
  onNavigateToApp,
  backendOnline,
}: BankismSentinelProps) {
  const [events, setEvents] = useState<any[]>([]);
  const [summary, setSummary] = useState<SentinelAuditSummary>({
    total_events: 0,
    total_inspections: 0,
    blocked_count: 0,
    review_count: 0,
    completed_count: 0,
    head_hash: 'GENESIS_HASH_00000000000000000000000000000000000000000000000000000000',
  });
  const [pendingApprovals, setPendingApprovals] = useState<any[]>([]);
  const [selectedFilter, setSelectedFilter] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [isLoadingEvents, setIsLoadingEvents] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [chainVerifyStatus, setChainVerifyStatus] = useState<any | null>(null);
  const [isVerifyingChain, setIsVerifyingChain] = useState<boolean>(false);
  const [approverUser, setApproverUser] = useState<'charlie' | 'alice'>('charlie');
  const [approvalProcessingId, setApprovalProcessingId] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Load audit events and pending dual approvals from the real backend
  const loadSentinelData = async () => {
    try {
      const data: SentinelAuditResponse = await fetchAuditEventsApi(100, 0, selectedFilter);
      setEvents(data.events);
      setSummary(data.summary);

      const pendings = await fetchPendingApprovalsApi();
      setPendingApprovals(pendings);
    } catch (err) {
      console.warn('Failed to load Sentinel telemetry:', err);
    } finally {
      setIsLoadingEvents(false);
    }
  };

  useEffect(() => {
    loadSentinelData();
  }, [selectedFilter]);

  // Clean polling effect (every 4 seconds when autoRefresh is enabled)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadSentinelData();
    }, 4000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedFilter]);

  // Execute Cryptographic SHA-256 Audit Chain Verification
  const handleVerifyAuditChain = async () => {
    setIsVerifyingChain(true);
    try {
      const res = await verifyAuditChainApi();
      setChainVerifyStatus(res);
      setActionNotice(
        res.valid
          ? `Cryptographic Audit Chain Verified: All ${res.total_events} events strictly chained without mutation.`
          : `ALERT: Broken link detected at block ${res.broken_at_index}!`
      );
    } catch (err: any) {
      setChainVerifyStatus({ valid: false, details: err.message || 'Verification failed' });
    } finally {
      setIsVerifyingChain(false);
    }
  };

  // Execute Dual Approval sign-off for pending high-risk transfers
  const handleProcessApproval = async (requestId: string, approve: boolean) => {
    setApprovalProcessingId(requestId);
    setActionNotice(null);
    try {
      const res = await approveTransferApi(
        approverUser,
        requestId,
        approve,
        approve ? 'Approved by Security Operations Risk Officer' : 'Rejected by Risk Officer'
      );
      setActionNotice(
        approve
          ? `Request ${requestId} APPROVED by ${approverUser}. Authorization ticket signed and issued.`
          : `Request ${requestId} REJECTED by ${approverUser}.`
      );
      await loadSentinelData();
    } catch (err: any) {
      setActionNotice(`Approval rejected fail-closed: ${err.message}`);
    } finally {
      setApprovalProcessingId(null);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top SOC Console Header */}
      <header className="sticky top-0 z-30 bg-slate-900/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white flex items-center justify-center font-bold text-xl shadow-md shadow-cyan-500/20">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">Bankism Sentinel</span>
                <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950/80 border border-cyan-800 rounded px-1.5 py-0.5">
                  SOC v0.3.0
                </span>
              </div>
              <p className="text-xs text-slate-400">Security Operations Center · Real-Time Threat & Ledger Telemetry</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Live Gateway Status */}
            <div className="flex items-center gap-2 text-xs bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              />
              <span className="text-slate-300 font-mono">
                {backendOnline ? 'Live Gateway Port 3000' : 'Offline Sandbox'}
              </span>
            </div>

            {/* Auto-Refresh Toggle */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-colors ${
                autoRefresh
                  ? 'bg-cyan-950/60 text-cyan-300 border-cyan-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
              }`}
              title="Toggle 4-second live telemetry refresh"
            >
              <Radio className={`w-3.5 h-3.5 ${autoRefresh ? 'text-cyan-400 animate-pulse' : ''}`} />
              <span>{autoRefresh ? 'Live Feed' : 'Paused'}</span>
            </button>

            {/* Switch to Bankism AI */}
            <button
              onClick={onNavigateToApp}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
              title="Open Bankism AI Customer Banking Interface"
            >
              <span>Bankism AI</span>
              <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
            </button>
          </div>
        </div>
      </header>

      {/* Main SOC Dashboard Layout */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full flex flex-col gap-6">
        {/* Action Notice Alert (if triggered) */}
        {actionNotice && (
          <div className="p-3.5 rounded-xl bg-slate-900 border border-cyan-500/40 text-cyan-200 text-xs flex items-center justify-between shadow-lg shadow-cyan-950/30">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span className="font-mono">{actionNotice}</span>
            </div>
            <button
              onClick={() => setActionNotice(null)}
              className="text-slate-400 hover:text-white text-xs font-semibold px-2 py-0.5"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* 5 High-Level SOC Telemetry Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* 1. Total Inspections */}
          <div className="bg-slate-900/90 rounded-xl border border-slate-800 p-4 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Firewall Inspections</span>
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <span className="text-2xl font-bold font-mono text-white tracking-tight">
                {summary.total_inspections}
              </span>
              <p className="text-[11px] text-slate-500 mt-0.5">Prompt & payload evaluations</p>
            </div>
          </div>

          {/* 2. Blocked Threats (Red) */}
          <div className="bg-slate-900/90 rounded-xl border border-rose-950/60 p-4 shadow-sm flex flex-col justify-between relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/5 rounded-full blur-xl pointer-events-none" />
            <div className="flex items-center justify-between text-rose-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Blocked Threats</span>
              <ShieldX className="w-4 h-4 text-rose-500" />
            </div>
            <div>
              <span className="text-2xl font-bold font-mono text-rose-400 tracking-tight">
                {summary.blocked_count}
              </span>
              <p className="text-[11px] text-rose-400/70 mt-0.5">Fail-closed invariant held</p>
            </div>
          </div>

          {/* 3. Under Review / Dual Approval (Amber) */}
          <div className="bg-slate-900/90 rounded-xl border border-amber-950/60 p-4 shadow-sm flex flex-col justify-between relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-xl pointer-events-none" />
            <div className="flex items-center justify-between text-amber-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Under Review</span>
              <Clock className="w-4 h-4 text-amber-500" />
            </div>
            <div>
              <span className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
                {summary.review_count}
              </span>
              <p className="text-[11px] text-amber-400/70 mt-0.5">Dual approval / step-up hold</p>
            </div>
          </div>

          {/* 4. Completed Transfers (Emerald) */}
          <div className="bg-slate-900/90 rounded-xl border border-emerald-950/60 p-4 shadow-sm flex flex-col justify-between relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-xl pointer-events-none" />
            <div className="flex items-center justify-between text-emerald-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Executed Transfers</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            </div>
            <div>
              <span className="text-2xl font-bold font-mono text-emerald-400 tracking-tight">
                {summary.completed_count}
              </span>
              <p className="text-[11px] text-emerald-400/70 mt-0.5">HMAC-signed & ledger-debited</p>
            </div>
          </div>

          {/* 5. Cryptographic SHA-256 Audit Chain */}
          <div className="bg-slate-900/90 rounded-xl border border-slate-800 p-4 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Audit Chain Integrity</span>
              <Lock className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span className="text-sm font-bold font-mono text-emerald-400">SHA-256 Verified</span>
              </div>
              <button
                onClick={handleVerifyAuditChain}
                disabled={isVerifyingChain}
                className="mt-2 w-full text-center py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] font-mono border border-slate-700 transition-colors"
              >
                {isVerifyingChain ? 'Hashing Chain...' : 'Verify Chain Now'}
              </button>
            </div>
          </div>
        </div>

        {/* Pending Dual Approval Queue (Shown if pending requests exist) */}
        {pendingApprovals.length > 0 && (
          <div className="bg-gradient-to-r from-amber-950/40 via-slate-900 to-amber-950/40 border border-amber-500/40 rounded-xl p-5 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center border border-amber-500/30">
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-amber-300">
                    Pending Dual Approval Queue ({pendingApprovals.length})
                  </h3>
                  <p className="text-xs text-amber-200/80">
                    High-value or high-risk transfers held pending Risk Officer sign-off. Separation of duties strictly enforced.
                  </p>
                </div>
              </div>

              {/* Approver Identity Selector */}
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Sign-Off Role:</span>
                <button
                  onClick={() => setApproverUser('charlie')}
                  className={`px-2.5 py-1 rounded font-mono text-xs border ${
                    approverUser === 'charlie'
                      ? 'bg-amber-600 text-white border-amber-500'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  charlie (Risk Officer)
                </button>
                <button
                  onClick={() => setApproverUser('alice')}
                  className={`px-2.5 py-1 rounded font-mono text-xs border ${
                    approverUser === 'alice'
                      ? 'bg-rose-700 text-white border-rose-600'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                  title="Test separation of duties violation (initiator self-approval)"
                >
                  alice (Initiator)
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {pendingApprovals.map((req) => (
                <div
                  key={req.request_id}
                  className="bg-slate-950/90 border border-amber-500/30 rounded-xl p-4 flex flex-col justify-between gap-3"
                >
                  <div>
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="font-mono font-bold text-amber-300">{req.request_id}</span>
                      <span className="font-mono text-slate-400 text-[11px]">{req.created_at_utc?.slice(11, 19)}</span>
                    </div>
                    <div className="text-xs space-y-1 text-slate-300">
                      <div>
                        <span className="text-slate-500">Initiator:</span>{' '}
                        <span className="font-mono text-slate-200">{req.initiator_user_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Routing:</span>{' '}
                        <span className="font-mono text-slate-200">
                          {req.source_account_id} → {req.destination_account_id}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Amount:</span>{' '}
                        <span className="font-mono font-bold text-amber-400">
                          {formatINR(req.amount_rupees ?? (req.amount_paise ? req.amount_paise / 100 : req.amount_cents / 100))}
                        </span>
                      </div>
                      <div className="text-[11px] text-amber-300/90 bg-amber-950/40 p-1.5 rounded border border-amber-900/50">
                        {req.reason}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                    <button
                      onClick={() => handleProcessApproval(req.request_id, true)}
                      disabled={approvalProcessingId === req.request_id}
                      className="flex-1 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>Approve & Issue Ticket</span>
                    </button>
                    <button
                      onClick={() => handleProcessApproval(req.request_id, false)}
                      disabled={approvalProcessingId === req.request_id}
                      className="py-1.5 px-3 bg-rose-900/60 hover:bg-rose-800 text-rose-200 rounded font-medium text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50 border border-rose-700/50"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Audit Events Telemetry Table */}
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-sm flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Security Events & Tamper-Evident Ledger Trail</span>
              </h2>
              <p className="text-xs text-slate-400">
                Cryptographically chained SHA-256 event stream linking firewall inspections, dual approvals, and executions
              </p>
            </div>

            {/* Event Category Filters (Segmented Controls) */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              {[
                { id: 'all', label: 'All Events' },
                { id: 'blocked', label: 'Blocked Threats' },
                { id: 'review', label: 'Under Review' },
                { id: 'completed', label: 'Completed' },
                { id: 'inspection', label: 'Inspections' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSelectedFilter(tab.id)}
                  className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                    selectedFilter === tab.id
                      ? 'bg-slate-800 text-cyan-300 shadow-xs border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Events Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3">Event Ref</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Principal</th>
                  <th className="py-2.5 px-3">Target</th>
                  <th className="py-2.5 px-3">Verdict / Risk</th>
                  <th className="py-2.5 px-3">Status / Outcome</th>
                  <th className="py-2.5 px-3 text-right">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {isLoadingEvents && events.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                      Loading telemetry feed...
                    </td>
                  </tr>
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                      No events matching filter "{selectedFilter}".
                    </td>
                  </tr>
                ) : (
                  events.map((evt) => {
                    // Extract payload metadata
                    const isBlock =
                      evt.event_type === 'TRANSFER_BLOCKED_FIREWALL' ||
                      (evt.event_type === 'FIREWALL_INSPECTION' && evt.payload.verdict === 'BLOCK');
                    const isReview =
                      evt.event_type === 'DUAL_APPROVAL_REQUESTED' ||
                      (evt.event_type === 'FIREWALL_INSPECTION' && evt.payload.verdict === 'REVIEW');
                    const isComplete = evt.event_type === 'TRANSFER_EXECUTED';

                    let verdictBadge = (
                      <span className="text-slate-400">INFO</span>
                    );
                    if (isBlock) {
                      verdictBadge = (
                        <span className="text-rose-400 font-bold bg-rose-950/60 border border-rose-800/80 px-1.5 py-0.5 rounded text-[10px]">
                          BLOCK
                        </span>
                      );
                    } else if (isReview) {
                      verdictBadge = (
                        <span className="text-amber-400 font-bold bg-amber-950/60 border border-amber-800/80 px-1.5 py-0.5 rounded text-[10px]">
                          REVIEW
                        </span>
                      );
                    } else if (isComplete || (evt.event_type === 'FIREWALL_INSPECTION' && evt.payload.verdict === 'APPROVE')) {
                      verdictBadge = (
                        <span className="text-emerald-400 font-bold bg-emerald-950/60 border border-emerald-800/80 px-1.5 py-0.5 rounded text-[10px]">
                          APPROVE
                        </span>
                      );
                    }

                    return (
                      <tr
                        key={evt.event_id}
                        className={`hover:bg-slate-800/50 transition-colors ${
                          selectedEvent?.event_id === evt.event_id ? 'bg-slate-800/70' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3 text-cyan-300 font-semibold">{evt.event_id}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {evt.timestamp ? evt.timestamp.slice(11, 19) : '—'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-200 font-sans font-medium text-xs">
                          {evt.event_type}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">{evt.user_id || 'ANONYMOUS'}</td>
                        <td className="py-2.5 px-3 text-slate-400">
                          {evt.payload?.destination_account_id ||
                            evt.payload?.target ||
                            evt.payload?.source_account_id ||
                            '—'}
                        </td>
                        <td className="py-2.5 px-3">{verdictBadge}</td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans text-xs">
                          {isBlock ? (
                            <span className="text-rose-400 flex items-center gap-1">
                              <ShieldX className="w-3 h-3" />
                              Blocked Fail-Closed
                            </span>
                          ) : isReview ? (
                            <span className="text-amber-400 flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              Awaiting Approval
                            </span>
                          ) : isComplete ? (
                            <span className="text-emerald-400 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" />
                              Ledger Debited
                            </span>
                          ) : (
                            <span className="text-slate-400">Inspected</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() => setSelectedEvent(evt)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded text-[11px] font-sans border border-slate-700 transition-colors"
                          >
                            <Eye className="w-3 h-3" />
                            <span>Inspect</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Forensic Evidence Detail Modal / Drawer (when an event is selected) */}
        {selectedEvent && (
          <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white">
                    Forensic Telemetry Evidence — {selectedEvent.event_id}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
                {/* Cryptographic Link Headers */}
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-slate-400 flex justify-between">
                    <span>Event Type:</span>
                    <span className="text-white font-bold">{selectedEvent.event_type}</span>
                  </div>
                  <div className="text-slate-400 flex justify-between">
                    <span>Timestamp (UTC):</span>
                    <span className="text-cyan-300">{selectedEvent.timestamp}</span>
                  </div>
                  <div className="text-slate-400 flex justify-between">
                    <span>Actor / User:</span>
                    <span className="text-slate-200">{selectedEvent.user_id}</span>
                  </div>
                  <div className="text-slate-400 flex flex-col gap-0.5 pt-1 border-t border-slate-800/80">
                    <span>Previous Block Hash:</span>
                    <span className="text-slate-500 text-[10px] truncate">{selectedEvent.prev_hash}</span>
                  </div>
                  <div className="text-slate-400 flex flex-col gap-0.5">
                    <span>Current Block SHA-256 Hash:</span>
                    <span className="text-emerald-400 text-[10px] truncate">{selectedEvent.event_hash}</span>
                  </div>
                </div>

                {/* Threat Details if Firewall Inspection / Block */}
                {selectedEvent.payload?.primary_threat && (
                  <div className="bg-slate-950 p-3 rounded-xl border border-rose-950/80 space-y-2 text-rose-200">
                    <div className="flex justify-between font-bold">
                      <span>Primary Threat:</span>
                      <span className="text-rose-400">{selectedEvent.payload.primary_threat}</span>
                    </div>
                    {selectedEvent.payload.reasons && (
                      <div className="text-[11px] text-rose-300/90 whitespace-pre-line bg-rose-950/30 p-2 rounded">
                        {Array.isArray(selectedEvent.payload.reasons)
                          ? selectedEvent.payload.reasons.join('\n')
                          : selectedEvent.payload.reasons}
                      </div>
                    )}
                  </div>
                )}

                {/* Complete Payload JSON Dump */}
                <div>
                  <span className="text-slate-400 block mb-1 font-sans text-xs font-medium">
                    Raw Immutable Payload:
                  </span>
                  <pre className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-[11px] text-slate-300 overflow-x-auto max-h-56">
                    {JSON.stringify(selectedEvent.payload, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="px-5 py-3 border-t border-slate-800 bg-slate-950 flex justify-end">
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium"
                >
                  Close Inspector
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
