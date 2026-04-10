'use client';

import { useState } from 'react';
import type { ScanFinding } from '@/lib/scoring';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ef4444',
  medium: '#f97316',
  low: '#eab308',
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
};

export default function FindingsList({ findings }: { findings: ScanFinding[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-mcp-green/30 bg-mcp-green/5 p-6 text-center">
        <p className="text-mcp-green font-semibold">No vulnerabilities detected</p>
        <p className="mt-1 text-sm text-slate-400">
          L0-L1 scan passed. Consider a full L2-L4 audit for production deployments.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {findings.map((f, i) => {
        const key = `${f.id}-${f.file}-${f.line}`;
        const isOpen = expanded === key;
        const color = SEVERITY_COLORS[f.severity] || '#94a3b8';
        const label = SEVERITY_LABELS[f.severity] || f.severity.toUpperCase();

        return (
          <div
            key={key}
            className="animate-slide-up rounded-lg border border-mcp-border bg-mcp-card overflow-hidden"
            style={{ animationDelay: `${i * 50}ms` }}
          >
            <button
              onClick={() => setExpanded(isOpen ? null : key)}
              className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm hover:bg-white/[0.02] transition-colors"
            >
              <span
                className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold"
                style={{
                  backgroundColor: color + '20',
                  color: color,
                }}
              >
                {label}
              </span>
              <span className="shrink-0 text-slate-500 text-xs">{f.id}</span>
              <span className="flex-1 truncate text-slate-200">{f.title}</span>
              {f.guardDetected && (
                <span className="shrink-0 rounded bg-mcp-green/10 px-1.5 py-0.5 text-[10px] text-mcp-green">
                  GUARDED
                </span>
              )}
              <span className="shrink-0 text-slate-500 text-xs">
                {f.file.split('/').pop()}:{f.line}
              </span>
              <svg
                className={`h-4 w-4 shrink-0 text-slate-500 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {isOpen && (
              <div className="border-t border-mcp-border px-4 py-3 text-xs space-y-2">
                <div>
                  <span className="text-slate-500">File: </span>
                  <span className="text-slate-300">{f.file}:{f.line}</span>
                </div>
                <div>
                  <span className="text-slate-500">Description: </span>
                  <span className="text-slate-300">{f.description}</span>
                </div>
                <div>
                  <span className="text-slate-500">Fix: </span>
                  <span className="text-slate-300">{f.recommendation}</span>
                </div>
                {f.owasp && (
                  <div>
                    <span className="text-slate-500">OWASP: </span>
                    <span className="text-slate-300">{f.owasp}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
