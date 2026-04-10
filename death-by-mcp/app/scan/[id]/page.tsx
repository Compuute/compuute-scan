'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import ScoreDisplay from '@/components/ScoreDisplay';
import FindingsList from '@/components/FindingsList';
import ShareCard from '@/components/ShareCard';
import type { ScanResult } from '@/lib/scoring';

export default function ScanResultPage() {
  const params = useParams();
  const rawId = params.id;
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showShare, setShowShare] = useState(false);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(`scan-${id}`);
      if (stored) {
        setResult(JSON.parse(stored));
      }
    } catch {
      // Corrupted data — show "not found" state
    }
  }, [id]);

  if (!result) {
    return (
      <div className="text-center py-24">
        <h1 className="text-2xl font-bold text-slate-200 mb-4">Scan not found</h1>
        <p className="text-slate-400 mb-6">
          This scan result may have expired or the URL is incorrect.
        </p>
        <a
          href="/"
          className="inline-block rounded-lg bg-mcp-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500"
        >
          Run a new scan
        </a>
      </div>
    );
  }

  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-2xl font-bold text-slate-200 mb-1">{result.repoName}</h1>
        <p className="text-sm text-slate-500 truncate">{result.repoUrl}</p>
      </div>

      {/* Score */}
      <ScoreDisplay result={result} />

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 max-w-2xl mx-auto">
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-4 text-center">
          <div className="text-2xl font-bold text-slate-200">{result.summary.total}</div>
          <div className="text-xs text-slate-500">Total</div>
        </div>
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-4 text-center">
          <div className="text-2xl font-bold text-red-500">{result.summary.critical}</div>
          <div className="text-xs text-slate-500">Critical</div>
        </div>
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-4 text-center">
          <div className="text-2xl font-bold text-red-400">{result.summary.high}</div>
          <div className="text-xs text-slate-500">High</div>
        </div>
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-4 text-center">
          <div className="text-2xl font-bold text-orange-400">{result.summary.medium}</div>
          <div className="text-xs text-slate-500">Medium</div>
        </div>
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-4 text-center">
          <div className="text-2xl font-bold text-yellow-400">{result.summary.low}</div>
          <div className="text-xs text-slate-500">Low</div>
        </div>
      </div>

      {/* Top findings */}
      {result.topFindings.length > 0 && (
        <div className="max-w-2xl mx-auto">
          <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-500 mb-4">
            Top vulnerabilities
          </h2>
          <FindingsList findings={result.topFindings} />
        </div>
      )}

      {/* All findings */}
      <div className="max-w-2xl mx-auto">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-500 mb-4">
          All findings ({result.findings.length})
        </h2>
        <FindingsList findings={result.findings} />
      </div>

      {/* Privacy notice */}
      <div className="max-w-2xl mx-auto rounded-lg border border-mcp-border/50 bg-mcp-card/50 px-4 py-3 text-xs text-slate-500 text-center">
        These results are private to your browser session. No data is stored on our servers.
        Sharing is optional and at your discretion.
      </div>

      {/* Scan metadata */}
      <div className="max-w-2xl mx-auto rounded-lg border border-mcp-border bg-mcp-card p-4 text-xs text-slate-500">
        <div className="grid grid-cols-2 gap-2">
          <div>Files scanned: {result.filesScanned}</div>
          <div>Layers: {result.layersCovered.join(', ')}</div>
          <div>
            Scanned:{' '}
            {new Date(result.scannedAt).toLocaleString()}
          </div>
          <div>Scan ID: {result.scanId}</div>
        </div>
      </div>

      {/* Share / Actions */}
      <div className="flex justify-center gap-4">
        <button
          onClick={() => setShowShare(!showShare)}
          className="rounded-lg border border-mcp-border bg-mcp-card px-5 py-2.5 text-sm text-slate-300 hover:bg-white/[0.03] transition-colors"
        >
          {showShare ? 'Hide card' : 'Share result'}
        </button>
        <a
          href="/"
          className="rounded-lg border border-mcp-border bg-mcp-card px-5 py-2.5 text-sm text-slate-300 hover:bg-white/[0.03] transition-colors"
        >
          Scan another
        </a>
      </div>

      {showShare && <ShareCard result={result} />}

      {/* CTA */}
      <div className="max-w-2xl mx-auto rounded-xl border border-mcp-accent/20 bg-mcp-accent/5 p-6 text-center">
        <p className="text-sm text-slate-400 mb-1">
          This scan covers <strong className="text-slate-200">L0-L1</strong> (Discovery + Sandboxing).
        </p>
        <p className="text-sm text-slate-400 mb-4">
          For full L2-L4 assessment with OWASP, NIS2, GDPR, and DORA compliance mapping:
        </p>
        <a
          href="https://compuute.se/audit"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block rounded-lg bg-mcp-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 transition-colors"
        >
          Book a Compuute Security Assessment
        </a>
      </div>
    </div>
  );
}
