'use client';

import { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function ScanForm() {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const router = useRouter();
  const logTimersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  // Clear all pending timers on unmount
  useEffect(() => () => logTimersRef.current.forEach(clearTimeout), []);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setScanning(true);
    setLogs([]);

    const trimmed = url.trim().replace(/\/+$/, '');
    if (!trimmed) {
      setError('Enter a GitHub, GitLab, or Bitbucket repository URL.');
      setScanning(false);
      return;
    }

    if (!consent) {
      setError('Please confirm you have the right to scan this repository.');
      setScanning(false);
      return;
    }

    // Simulate terminal output
    const repoName = trimmed.split('/').pop() || 'repo';
    setLogs(['$ compuute-scan ' + repoName]);

    logTimersRef.current = [];
    const addLog = (msg: string, delay: number) =>
      new Promise<void>((resolve) => {
        const t = setTimeout(() => {
          setLogs((prev) => [...prev, msg]);
          resolve();
        }, delay);
        logTimersRef.current.push(t);
      });

    try {
      // Start scan animation
      addLog('Cloning repository...', 400);
      addLog('Scanning source files...', 1200);
      addLog('Running L0 Discovery...', 2000);
      addLog('Running L1 Sandboxing rules...', 2800);

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: trimmed }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Scan failed.');
        setScanning(false);
        logTimersRef.current.forEach(clearTimeout);
        return;
      }

      // Store result in sessionStorage for the results page
      sessionStorage.setItem(`scan-${data.scanId}`, JSON.stringify(data));

      setLogs((prev) => [
        ...prev,
        `Scan complete: ${data.findings.length} findings, score ${data.score}/100`,
      ]);

      // Navigate to results
      setTimeout(() => {
        router.push(`/scan/${data.scanId}`);
      }, 500);
    } catch {
      setError('Network error. Please try again.');
      setScanning(false);
      logTimers.forEach(clearTimeout);
    }
  }

  return (
    <div>
      <form onSubmit={handleScan} className="space-y-3">
        <div className="flex gap-3">
          <input
            type="url"
            placeholder="https://github.com/org/mcp-server (also GitLab, Bitbucket)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
            className="flex-1 rounded-lg border border-mcp-border bg-mcp-card px-4 py-3 text-sm text-slate-200 placeholder:text-slate-500 focus:border-mcp-accent focus:outline-none focus:ring-1 focus:ring-mcp-accent disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={scanning || !consent}
            className="rounded-lg bg-mcp-accent px-6 py-3 text-sm font-semibold text-white transition-all hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>
        <label className="flex items-start gap-2.5 cursor-pointer group">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            disabled={scanning}
            className="mt-0.5 h-4 w-4 rounded border-mcp-border bg-mcp-card accent-mcp-accent"
          />
          <span className="text-xs text-slate-500 group-hover:text-slate-400 transition-colors leading-relaxed">
            I confirm that I own this repository or have permission to scan it.
            Results are shown only to me and are not stored.{' '}
            <a href="/about#responsible-disclosure" className="text-mcp-accent hover:underline">
              Responsible disclosure policy
            </a>
          </span>
        </label>
      </form>

      {error && (
        <div className="mt-4 rounded-lg border border-mcp-red/30 bg-mcp-red/10 px-4 py-3 text-sm text-mcp-red">
          {error}
        </div>
      )}

      {scanning && logs.length > 0 && (
        <div className="mt-6 rounded-lg border border-mcp-border bg-mcp-card p-4 font-mono text-xs text-slate-400">
          {logs.map((log, i) => (
            <div key={i} className="animate-fade-in">
              <span className="text-mcp-accent">{'>'}</span> {log}
            </div>
          ))}
          <div className="cursor-blink mt-1 text-slate-500" />
        </div>
      )}
    </div>
  );
}
