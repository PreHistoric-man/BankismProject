/**
 * @file MoneyTransferFlowVisualizer.tsx
 * @description Real-Time Visual Money-Transfer Flow Component for Bankism AI & Sentinel
 *
 * Visualizes account-to-account money movement:
 * - Source and Recipient account cards with real before/after ledger balances
 * - Directional animated flow line with moving currency token respecting prefers-reduced-motion
 * - Explicit 7-stage backend lifecycle stepper based on verified backend responses
 * - Stop states for BLOCKED, AWAITING APPROVAL, FAILED, and COMPLETED
 * - Adaptive Trust Engine score and explainable signals integration
 * - Adaptable light/dark themes for Bankism AI consumer interface and Sentinel SOC dashboard
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ArrowRight,
  Lock,
  Database,
  Terminal,
  Activity,
  AlertTriangle,
  XCircle,
  Layers,
  Sparkles,
  ChevronRight,
  Check,
  ShieldX,
} from 'lucide-react';
import { formatINR } from '../api';

export type TransferLifecycleStage =
  | 'PROPOSED'
  | 'CONFIRMING'
  | 'PENDING_APPROVAL'
  | 'COMPLETED'
  | 'BLOCKED'
  | 'FAILED';

export interface MoneyTransferFlowProps {
  stage: TransferLifecycleStage;
  amount: number;
  currency?: string;
  sourceAccount: {
    accountId: string;
    name?: string;
    balanceBefore?: number;
    balanceAfter?: number;
  };
  destinationAccount: {
    accountId: string;
    name?: string;
    balanceBefore?: number | null;
    balanceAfter?: number | null;
    existsInLedger?: boolean;
  };
  transactionId?: string;
  auditHash?: string;
  riskAssessment?: {
    score?: number;
    level?: string;
    confidence?: number;
    profileStatus?: string;
    signals?: Array<{ id: string; name: string; explanation?: string; score?: number }>;
    explanations?: string[];
  } | null;
  reasons?: string[];
  isCompact?: boolean;
  theme?: 'light' | 'dark';
}

export default function MoneyTransferFlowVisualizer({
  stage,
  amount,
  currency = 'INR',
  sourceAccount,
  destinationAccount,
  transactionId,
  auditHash,
  riskAssessment,
  reasons,
  isCompact = false,
  theme = 'dark',
}: MoneyTransferFlowProps) {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
      setPrefersReducedMotion(mediaQuery.matches);
      const listener = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
      mediaQuery.addEventListener('change', listener);
      return () => mediaQuery.removeEventListener('change', listener);
    }
  }, []);

  const isCompleted = stage === 'COMPLETED';
  const isBlocked = stage === 'BLOCKED';
  const isPendingApproval = stage === 'PENDING_APPROVAL';
  const isConfirming = stage === 'CONFIRMING';
  const isFailed = stage === 'FAILED';
  const isProposed = stage === 'PROPOSED';

  const isDark = theme === 'dark';

  // Explicit 7 backend lifecycle stages
  const lifecycleSteps = [
    {
      step: 1,
      title: 'Proposal Prepared',
      description: 'Request parsed & parameters bound',
      state: 'DONE',
    },
    {
      step: 2,
      title: 'Firewall Inspection',
      description: isBlocked ? 'Threat detected: execution halted' : 'Deterministic inspection passed',
      state: isBlocked ? 'BLOCKED' : isProposed ? 'WAITING' : isConfirming ? 'ACTIVE' : 'DONE',
    },
    {
      step: 3,
      title: 'Adaptive Trust Assessment',
      description: isBlocked ? 'Skipped: halted at firewall' : 'Personal baseline & anomalies evaluated',
      state: isBlocked ? 'SKIPPED' : isProposed ? 'WAITING' : isConfirming ? 'ACTIVE' : 'DONE',
    },
    {
      step: 4,
      title: 'Policy Gate & Approval',
      description: isBlocked
        ? 'Skipped'
        : isPendingApproval
        ? 'High-risk hold: secondary sign-off needed'
        : 'Policy checks satisfied',
      state: isBlocked
        ? 'SKIPPED'
        : isProposed
        ? 'WAITING'
        : isPendingApproval
        ? 'HOLD'
        : isConfirming
        ? 'ACTIVE'
        : 'DONE',
    },
    {
      step: 5,
      title: 'HMAC Authorization',
      description: isCompleted ? 'Cryptographic ticket signed & verified' : 'Awaiting ticket validation',
      state: isBlocked || isPendingApproval
        ? 'SKIPPED'
        : isProposed
        ? 'WAITING'
        : isFailed
        ? 'FAILED'
        : isConfirming
        ? 'ACTIVE'
        : isCompleted
        ? 'DONE'
        : 'WAITING',
    },
    {
      step: 6,
      title: 'Atomic Ledger Commit',
      description: isCompleted ? 'Debit & credit committed atomically' : 'Balances unchanged',
      state: isCompleted ? 'DONE' : isFailed ? 'FAILED' : 'WAITING',
    },
    {
      step: 7,
      title: 'Audit Event Confirmed',
      description: isCompleted
        ? 'SHA-256 block linked in audit chain'
        : isBlocked
        ? 'TRANSFER_BLOCKED_FIREWALL recorded'
        : isPendingApproval
        ? 'DUAL_APPROVAL_REQUESTED recorded'
        : 'Pending final record',
      state: isCompleted || isBlocked || isPendingApproval ? 'DONE' : 'WAITING',
    },
  ];

  return (
    <div
      className={`w-full rounded-xl p-3.5 sm:p-4 border shadow-xs flex flex-col gap-3 font-sans transition-colors ${
        isDark
          ? 'bg-slate-900/95 text-slate-100 border-slate-800'
          : 'bg-white text-slate-900 border-slate-200'
      }`}
    >
      {/* Header status badge & amount banner */}
      <div
        className={`flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b text-xs ${
          isDark ? 'border-slate-800' : 'border-slate-200'
        }`}
      >
        <div className="flex items-center gap-2">
          <span className={`font-semibold text-xs ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
            Money Movement Flow:
          </span>
          {isCompleted && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-bold text-[11px] bg-emerald-950/80 text-emerald-400 border border-emerald-700/80">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>COMPLETED & COMMITTED</span>
            </span>
          )}
          {isBlocked && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-bold text-[11px] bg-rose-950/80 text-rose-400 border border-rose-700/80">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>BLOCKED FAIL-CLOSED</span>
            </span>
          )}
          {isPendingApproval && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-bold text-[11px] bg-amber-950/80 text-amber-400 border border-amber-700/80">
              <Clock className="w-3.5 h-3.5" />
              <span>AWAITING APPROVAL</span>
            </span>
          )}
          {isConfirming && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-bold text-[11px] bg-blue-950/80 text-cyan-300 border border-blue-700/80 animate-pulse">
              <Activity className="w-3.5 h-3.5 animate-spin" />
              <span>INSPECTING & AUTHORIZING...</span>
            </span>
          )}
          {isFailed && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-bold text-[11px] bg-rose-950/80 text-rose-400 border border-rose-700/80">
              <XCircle className="w-3.5 h-3.5" />
              <span>EXECUTION FAILED</span>
            </span>
          )}
          {isProposed && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-medium text-[11px] bg-blue-50 text-blue-700 border border-blue-200">
              <Lock className="w-3.5 h-3.5 text-blue-600" />
              <span>PROPOSAL AWAITING CONFIRMATION</span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className={`text-[11px] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Transfer Amount:
          </span>
          <span
            className={`font-bold font-mono text-sm sm:text-base ${
              isDark ? 'text-amber-400' : 'text-blue-700'
            }`}
          >
            {formatINR(amount)} {currency}
          </span>
        </div>
      </div>

      {/* Account-to-Account Directional Flow Visualization */}
      <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center py-2">
        {/* Source Account Card (5 cols on md) */}
        <div
          className={`md:col-span-5 rounded-xl p-3 flex flex-col gap-2 relative overflow-hidden border ${
            isDark
              ? 'bg-slate-950/80 border-slate-800'
              : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center justify-between text-xs">
            <span
              className={`text-[10px] uppercase tracking-wider font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-500'
              }`}
            >
              Source Account (Debited)
            </span>
            <span
              className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${
                isDark
                  ? 'bg-blue-950/60 text-blue-400 border-blue-800/60'
                  : 'bg-blue-100 text-blue-700 border-blue-200'
              }`}
            >
              SENDER
            </span>
          </div>

          <div>
            <h4 className={`font-semibold text-sm ${isDark ? 'text-white' : 'text-slate-900'}`}>
              {sourceAccount.name || 'Primary Checking'}
            </h4>
            <span className="font-mono text-xs text-slate-500">{sourceAccount.accountId}</span>
          </div>

          {/* Source Ledger Balances Before / After */}
          <div
            className={`pt-2 border-t grid grid-cols-2 gap-2 text-[11px] ${
              isDark ? 'border-slate-800/80' : 'border-slate-200'
            }`}
          >
            <div>
              <span className="text-slate-500 block text-[10px]">Balance Before:</span>
              <span className={`font-mono font-medium ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                {sourceAccount.balanceBefore !== undefined
                  ? formatINR(sourceAccount.balanceBefore)
                  : '—'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Balance After:</span>
              {isCompleted && sourceAccount.balanceAfter !== undefined ? (
                <span className="font-mono font-bold text-emerald-500">
                  {formatINR(sourceAccount.balanceAfter)}
                </span>
              ) : isBlocked || isPendingApproval || isFailed ? (
                <span className="font-mono text-slate-500 text-[10px]">
                  Unchanged (₹0.00 debited)
                </span>
              ) : (
                <span className="font-mono text-slate-400 text-[10px] italic">
                  Pending Execution
                </span>
              )}
            </div>
          </div>

          {/* Debit delta tag */}
          {isCompleted && (
            <div className="text-[10px] font-mono text-rose-500 bg-rose-50 dark:bg-rose-950/40 px-2 py-0.5 rounded border border-rose-200 dark:border-rose-900/40 inline-flex items-center gap-1 self-start font-semibold">
              <span>Debit: -{formatINR(amount)}</span>
            </div>
          )}
        </div>

        {/* Directional Connector & Flow Animation (1 col on md) */}
        <div className="md:col-span-1 flex flex-col items-center justify-center py-2 relative">
          <div className="w-full flex md:flex-col items-center justify-center gap-1 relative">
            {/* Desktop Horizontal Line connecting Cards */}
            <div
              className={`hidden md:block w-full h-1 relative overflow-hidden rounded-full ${
                isDark ? 'bg-slate-800' : 'bg-slate-300'
              }`}
            >
              {/* Flowing animated token/particle (respects prefersReducedMotion) */}
              {isCompleted && !prefersReducedMotion && (
                <div
                  className="h-full w-1/2 bg-gradient-to-r from-transparent via-emerald-400 to-transparent absolute"
                  style={{
                    animation: 'flowRight 1.4s ease-in-out infinite',
                  }}
                />
              )}
            </div>

            {/* Mobile Vertical Line */}
            <div
              className={`md:hidden w-1 h-8 relative overflow-hidden rounded-full my-1 ${
                isDark ? 'bg-slate-800' : 'bg-slate-300'
              }`}
            >
              {isCompleted && !prefersReducedMotion && (
                <div
                  className="w-full h-1/2 bg-gradient-to-b from-transparent via-emerald-400 to-transparent absolute"
                  style={{
                    animation: 'flowDown 1.4s ease-in-out infinite',
                  }}
                />
              )}
            </div>

            {/* Central Animated Currency Token / Status Badge */}
            <div
              className={`w-9 h-9 rounded-full flex items-center justify-center font-bold text-xs shadow-md transition-all ${
                isCompleted
                  ? 'bg-emerald-600 text-white shadow-emerald-500/30 scale-105'
                  : isBlocked
                  ? 'bg-rose-600 text-white shadow-rose-500/30'
                  : isPendingApproval
                  ? 'bg-amber-500 text-white shadow-amber-500/30'
                  : isConfirming
                  ? 'bg-blue-600 text-white animate-pulse'
                  : isDark
                  ? 'bg-slate-800 text-slate-300 border border-slate-700'
                  : 'bg-white text-slate-700 border border-slate-300 shadow-xs'
              }`}
              title={
                isCompleted
                  ? 'Transfer Executed Atomically'
                  : isBlocked
                  ? 'Blocked at Firewall'
                  : isPendingApproval
                  ? 'Awaiting Approval'
                  : 'Currency Movement Gateway'
              }
            >
              {isCompleted ? (
                <CheckCircle2 className="w-5 h-5 text-white" />
              ) : isBlocked ? (
                <ShieldX className="w-5 h-5 text-white" />
              ) : isPendingApproval ? (
                <Clock className="w-5 h-5 text-white" />
              ) : (
                <span className="font-mono font-bold text-sm">₹</span>
              )}
            </div>
          </div>
        </div>

        {/* Recipient Account Card (5 cols on md) */}
        <div
          className={`md:col-span-5 rounded-xl p-3 flex flex-col gap-2 relative overflow-hidden border ${
            isDark
              ? 'bg-slate-950/80 border-slate-800'
              : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center justify-between text-xs">
            <span
              className={`text-[10px] uppercase tracking-wider font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-500'
              }`}
            >
              Recipient Account (Credited)
            </span>
            <span
              className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${
                destinationAccount.existsInLedger !== false
                  ? isDark
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                    : 'bg-emerald-100 text-emerald-700 border-emerald-200'
                  : isDark
                  ? 'bg-slate-800 text-slate-400 border-slate-700'
                  : 'bg-slate-200 text-slate-600 border-slate-300'
              }`}
            >
              {destinationAccount.existsInLedger !== false ? 'INTERNAL LEDGER' : 'EXTERNAL'}
            </span>
          </div>

          <div>
            <h4 className={`font-semibold text-sm ${isDark ? 'text-white' : 'text-slate-900'}`}>
              {destinationAccount.name || 'Recipient Account'}
            </h4>
            <span className="font-mono text-xs text-slate-500">{destinationAccount.accountId}</span>
          </div>

          {/* Destination Ledger Balances Before / After */}
          <div
            className={`pt-2 border-t grid grid-cols-2 gap-2 text-[11px] ${
              isDark ? 'border-slate-800/80' : 'border-slate-200'
            }`}
          >
            <div>
              <span className="text-slate-500 block text-[10px]">Balance Before:</span>
              <span className={`font-mono font-medium ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                {destinationAccount.balanceBefore !== null &&
                destinationAccount.balanceBefore !== undefined
                  ? formatINR(destinationAccount.balanceBefore)
                  : destinationAccount.existsInLedger === false
                  ? 'External Counterparty'
                  : '—'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Balance After:</span>
              {isCompleted ? (
                destinationAccount.balanceAfter !== null &&
                destinationAccount.balanceAfter !== undefined ? (
                  <span className="font-mono font-bold text-emerald-500">
                    {formatINR(destinationAccount.balanceAfter)}
                  </span>
                ) : (
                  <span className="font-mono text-emerald-500 text-[10px] font-semibold">
                    Settled via Settlement
                  </span>
                )
              ) : isBlocked || isPendingApproval || isFailed ? (
                <span className="font-mono text-slate-500 text-[10px]">
                  Unchanged (₹0.00 credited)
                </span>
              ) : (
                <span className="font-mono text-slate-400 text-[10px] italic">
                  Pending Execution
                </span>
              )}
            </div>
          </div>

          {/* Credit delta tag */}
          {isCompleted && (
            <div className="text-[10px] font-mono text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-200 dark:border-emerald-900/40 inline-flex items-center gap-1 self-start font-semibold">
              <span>Credit: +{formatINR(amount)}</span>
            </div>
          )}
        </div>
      </div>

      {/* Explicit 7-Step Backend Lifecycle Stepper */}
      {!isCompact && (
        <div className={`pt-2 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
          <div className="flex items-center justify-between text-[11px] mb-2">
            <span
              className={`font-semibold flex items-center gap-1.5 ${
                isDark ? 'text-slate-300' : 'text-slate-700'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-blue-500" />
              Backend Execution Lifecycle Stepper:
            </span>
            <span className="font-mono text-[10px] text-slate-500">
              {isCompleted
                ? 'Step 7 of 7 Confirmed'
                : isBlocked
                ? 'Halted at Step 2 (Firewall BLOCKED)'
                : isPendingApproval
                ? 'Held at Step 4 (Policy Gate Review)'
                : isConfirming
                ? 'Verifying Step 5'
                : 'Awaiting User Confirmation'}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-1.5 text-[10px]">
            {lifecycleSteps.map((s) => {
              let badgeStyle = isDark
                ? 'bg-slate-950 border-slate-800 text-slate-500'
                : 'bg-slate-100 border-slate-200 text-slate-400';

              if (s.state === 'DONE') {
                badgeStyle = isDark
                  ? 'bg-emerald-950/70 border-emerald-800/80 text-emerald-300'
                  : 'bg-emerald-50 border-emerald-200 text-emerald-800';
              } else if (s.state === 'BLOCKED') {
                badgeStyle = isDark
                  ? 'bg-rose-950/80 border-rose-800 text-rose-300 font-bold'
                  : 'bg-rose-50 border-rose-200 text-rose-800 font-bold';
              } else if (s.state === 'HOLD') {
                badgeStyle = isDark
                  ? 'bg-amber-950/80 border-amber-800 text-amber-300 font-bold'
                  : 'bg-amber-50 border-amber-300 text-amber-900 font-bold';
              } else if (s.state === 'ACTIVE') {
                badgeStyle = isDark
                  ? 'bg-blue-950/80 border-cyan-800 text-cyan-300 animate-pulse font-bold'
                  : 'bg-blue-50 border-blue-300 text-blue-800 animate-pulse font-bold';
              } else if (s.state === 'FAILED') {
                badgeStyle = isDark
                  ? 'bg-rose-950/80 border-rose-800 text-rose-300'
                  : 'bg-rose-50 border-rose-200 text-rose-800';
              }

              return (
                <div
                  key={s.step}
                  className={`p-1.5 rounded-lg border flex flex-col justify-between gap-1 ${badgeStyle}`}
                >
                  <div className="flex justify-between items-center text-[9px]">
                    <span className="font-mono opacity-80">{s.step}.</span>
                    {s.state === 'DONE' && <CheckCircle2 className="w-2.5 h-2.5 text-emerald-500" />}
                    {s.state === 'BLOCKED' && <ShieldAlert className="w-2.5 h-2.5 text-rose-500" />}
                    {s.state === 'HOLD' && <Clock className="w-2.5 h-2.5 text-amber-500" />}
                    {s.state === 'ACTIVE' && <Activity className="w-2.5 h-2.5 text-blue-500 animate-spin" />}
                  </div>
                  <span className="font-medium leading-tight truncate">{s.title}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Adaptive Trust Telemetry Bar & Explanations (when available) */}
      {riskAssessment && (
        <div
          className={`rounded-lg p-2.5 border text-[11px] space-y-1.5 ${
            isDark
              ? 'bg-slate-950/80 border-slate-800/90'
              : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-500" />
              <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                Adaptive Trust Assessment:
              </span>
              <span
                className={`font-mono font-bold px-1.5 py-0.5 rounded text-[10px] border ${
                  riskAssessment.level === 'CRITICAL'
                    ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                    : riskAssessment.level === 'HIGH'
                    ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                    : 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                }`}
              >
                {riskAssessment.level || 'LOW'} ({riskAssessment.score ?? 5}/100)
              </span>
            </div>
            {riskAssessment.confidence !== undefined && (
              <span className="text-[10px] text-slate-500 font-mono">
                Maturity: {riskAssessment.profileStatus || 'MATURE'} · Conf:{' '}
                {Math.round(riskAssessment.confidence * 100)}%
              </span>
            )}
          </div>

          {/* Contributing explainable signals */}
          {((riskAssessment.signals && riskAssessment.signals.length > 0) ||
            (riskAssessment.explanations && riskAssessment.explanations.length > 0) ||
            (reasons && reasons.length > 0)) && (
            <div className="text-[11px] space-y-1 pt-0.5">
              {riskAssessment.signals && riskAssessment.signals.length > 0 ? (
                riskAssessment.signals.map((sig, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                    <span className="text-amber-500 font-bold">•</span>
                    <span className={isDark ? 'text-slate-300' : 'text-slate-700'}>
                      <strong>{sig.name || sig.id}:</strong> {sig.explanation}
                    </span>
                  </div>
                ))
              ) : (riskAssessment.explanations || reasons)?.map((exp, idx) => (
                <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                  <span className="text-amber-500 font-bold">•</span>
                  <span className={isDark ? 'text-slate-300' : 'text-slate-700'}>{exp}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Transaction & Audit Evidence Receipt Footer (When executed) */}
      {isCompleted && transactionId && (
        <div
          className={`rounded-lg p-2 border text-[10px] font-mono flex flex-wrap items-center justify-between gap-2 ${
            isDark
              ? 'bg-emerald-950/40 border-emerald-900/60 text-emerald-300'
              : 'bg-emerald-50 border-emerald-200 text-emerald-800'
          }`}
        >
          <div>
            <span className="text-slate-500 font-sans">Tx Reference:</span>{' '}
            <span className="font-bold">{transactionId}</span>
          </div>
          {auditHash && (
            <div className="truncate max-w-[280px]">
              <span className="text-slate-500 font-sans">SHA-256 Audit Link:</span>{' '}
              <span className="font-mono">{auditHash}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
