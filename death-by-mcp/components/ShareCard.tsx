'use client';

import { getRiskLabel } from '@/lib/scoring';
import type { ScanResult } from '@/lib/scoring';

export default function ShareCard({ result }: { result: ScanResult }) {
  const date = new Date(result.scannedAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });

  const isClean = result.score === 0;

  return (
    <div className="rounded-xl border border-mcp-border bg-mcp-card p-6 max-w-md mx-auto">
      <div className="text-center">
        {/* Header */}
        <div className="text-xs text-slate-500 uppercase tracking-widest mb-4">
          {isClean ? 'Clean Bill of Health' : 'Death Certificate'}
        </div>

        {/* Shield icon */}
        <div className="mb-3">
          <svg
            width="48"
            height="48"
            viewBox="0 0 24 24"
            fill="none"
            stroke={result.riskColor}
            strokeWidth="1.5"
            className="mx-auto"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            {isClean ? (
              <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
            ) : (
              <>
                <path d="M15 9l-6 6" strokeLinecap="round" />
                <path d="M9 9l6 6" strokeLinecap="round" />
              </>
            )}
          </svg>
        </div>

        {/* Repo name */}
        <div className="font-bold text-lg text-slate-200 mb-1">{result.repoName}</div>
        <div className="text-xs text-slate-500 mb-4 truncate">{result.repoUrl}</div>

        {/* Score */}
        <div
          className="text-5xl font-bold mb-1"
          style={{ color: result.riskColor }}
        >
          {result.score}
        </div>
        <div
          className="text-sm font-semibold mb-4"
          style={{ color: result.riskColor }}
        >
          {getRiskLabel(result.riskLevel)}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-2 text-center text-xs mb-4">
          <div>
            <div className="text-lg font-bold text-red-500">{result.summary.critical}</div>
            <div className="text-slate-500">Critical</div>
          </div>
          <div>
            <div className="text-lg font-bold text-red-400">{result.summary.high}</div>
            <div className="text-slate-500">High</div>
          </div>
          <div>
            <div className="text-lg font-bold text-orange-400">{result.summary.medium}</div>
            <div className="text-slate-500">Medium</div>
          </div>
          <div>
            <div className="text-lg font-bold text-yellow-400">{result.summary.low}</div>
            <div className="text-slate-500">Low</div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-mcp-border pt-3 text-[10px] text-slate-500">
          Scanned by compuute-scan v0.3.0 | compuute.se | {date}
        </div>
      </div>
    </div>
  );
}
