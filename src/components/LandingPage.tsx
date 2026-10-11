/**
 * @file LandingPage.tsx
 * @description Shared Landing Portal for Bankism
 * Connects Bankism AI (Conversational Banking) and Bankism Sentinel (Security Operations Center).
 */

import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  MessageSquare,
  Lock,
  ArrowRight,
  Activity,
  Terminal,
  Zap,
  CheckCircle2,
  Cpu,
  Layers,
  Database,
  Sliders,
  ExternalLink,
} from 'lucide-react';

interface LandingPageProps {
  onSelectApp: () => void;
  onSelectSentinel: () => void;
  onSelectLegacyDemo: () => void;
  backendOnline: boolean;
}

export default function LandingPage({
  onSelectApp,
  onSelectSentinel,
  onSelectLegacyDemo,
  backendOnline,
}: LandingPageProps) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-500/30 selection:text-blue-200">
      {/* Top Bar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-lg shadow-sm">
              B
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight text-white">Bankism</span>
              <span className="ml-2 font-mono text-xs text-blue-400 bg-blue-950/80 border border-blue-900 rounded px-1.5 py-0.5">
                Dual Product Suite
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              />
              <span className="text-slate-300 font-mono">
                {backendOnline ? 'Gateway Connected (Port 3000)' : 'Simulated Sandbox'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 flex flex-col justify-center">
        <div className="text-center max-w-3xl mx-auto mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-950/80 border border-blue-800/80 text-blue-300 text-xs font-medium mb-4">
            <Lock className="w-3.5 h-3.5" />
            <span>Defensive AI Security Firewall & Protected Transaction Gateway</span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight mb-4">
            One Core Engine. <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
              Two Distinct Real Product Experiences.
            </span>
          </h1>
          <p className="text-base text-slate-400 leading-relaxed">
            Bankism intercepts untrusted natural-language prompts before they can reach privileged banking operations.
            Experience the consumer conversational banking interface coordinated directly with the live Security Operations Center.
          </p>
        </div>

        {/* Product Split Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl mx-auto w-full mb-14">
          {/* 1. Bankism AI Card */}
          <div className="bg-gradient-to-b from-slate-900 to-slate-900/90 rounded-2xl border border-slate-800 p-8 shadow-xl flex flex-col justify-between hover:border-blue-500/50 transition-all group">
            <div>
              <div className="w-12 h-12 rounded-xl bg-blue-600/20 text-blue-400 flex items-center justify-center mb-6 border border-blue-500/30 group-hover:bg-blue-600 group-hover:text-white transition-all">
                <MessageSquare className="w-6 h-6" />
              </div>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-blue-400">Route /app</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs text-slate-400">Consumer Experience</span>
              </div>
              <h2 className="text-2xl font-bold text-white mb-3">Bankism AI</h2>
              <p className="text-sm text-slate-400 leading-relaxed mb-6">
                Polished conversational banking interface where customers check balances, review transactions, and request transfers. Requests are interpreted into review proposals and verified through pre-execution firewall checks.
              </p>

              <div className="space-y-2.5 text-xs text-slate-300 mb-8 border-t border-slate-800/80 pt-4">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>Natural-language balance & transaction queries</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>Mandatory structured review card before execution</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>Strict decoupling: LLM cannot debit ledger directly</span>
                </div>
              </div>
            </div>

            <button
              onClick={onSelectApp}
              className="w-full py-3.5 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold text-sm flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
            >
              <span>Launch Bankism AI (/app)</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* 2. Bankism Sentinel Card */}
          <div className="bg-gradient-to-b from-slate-900 to-slate-900/90 rounded-2xl border border-slate-800 p-8 shadow-xl flex flex-col justify-between hover:border-cyan-500/50 transition-all group">
            <div>
              <div className="w-12 h-12 rounded-xl bg-cyan-600/20 text-cyan-400 flex items-center justify-center mb-6 border border-cyan-500/30 group-hover:bg-cyan-600 group-hover:text-white transition-all">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-cyan-400">Route /sentinel</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs text-slate-400">Security Operations (SOC)</span>
              </div>
              <h2 className="text-2xl font-bold text-white mb-3">Bankism Sentinel</h2>
              <p className="text-sm text-slate-400 leading-relaxed mb-6">
                Real-time security operations console for analysts and risk officers. Inspect firewall decisions, observe prompt injection blocks, review high-risk transfers, and cryptographically verify the SHA-256 ledger chain.
              </p>

              <div className="space-y-2.5 text-xs text-slate-300 mb-8 border-t border-slate-800/80 pt-4">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Live telemetry on blocked threats & prompt injections</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Pending Dual Approval queue for Risk Officers</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Genesis-to-Head SHA-256 audit chain verification</span>
                </div>
              </div>
            </div>

            <button
              onClick={onSelectSentinel}
              className="w-full py-3.5 px-4 bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-white rounded-xl font-semibold text-sm flex items-center justify-center gap-2 border border-slate-700 hover:border-cyan-500/50 transition-all"
            >
              <span>Launch Bankism Sentinel (/sentinel)</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Security Invariants Footer Banner */}
        <div className="bg-slate-900/60 rounded-xl border border-slate-800/80 p-5 max-w-5xl mx-auto w-full flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-4">
            <span className="text-slate-200 font-semibold flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Core Invariants Enforced:
            </span>
            <span className="hidden md:inline">POL-001 (Injection Block)</span>
            <span className="hidden md:inline">·</span>
            <span className="hidden md:inline">POL-005 (Dual Approval &gt;₹50k)</span>
            <span className="hidden md:inline">·</span>
            <span className="hidden md:inline">HMAC-Signed Tickets</span>
          </div>

          <button
            onClick={onSelectLegacyDemo}
            className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1 transition-colors self-start sm:self-auto"
          >
            <span>Hackathon Benchmark Suite & Playground</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      </main>
    </div>
  );
}
