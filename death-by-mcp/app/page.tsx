import ScanForm from '@/components/ScanForm';

export default function Home() {
  return (
    <div className="flex flex-col items-center">
      {/* Hero */}
      <div className="text-center max-w-2xl mb-12">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl mb-4">
          How secure is your{' '}
          <span className="text-mcp-accent">MCP server</span>?
        </h1>
        <p className="text-lg text-slate-400 mb-2">
          Paste a GitHub repo URL. Get a security score in 30 seconds.
        </p>
        <p className="text-sm text-slate-500">
          Supports TypeScript, JavaScript, Python, and Go &mdash; 81% of the MCP ecosystem.
        </p>
      </div>

      {/* Scan form */}
      <div className="w-full max-w-2xl mb-16">
        <ScanForm />
      </div>

      {/* How it works */}
      <div className="w-full max-w-3xl">
        <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-slate-500 mb-8">
          How it works
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-5 text-center">
            <div className="text-2xl mb-3">1</div>
            <h3 className="font-semibold text-slate-200 mb-1">Paste URL</h3>
            <p className="text-xs text-slate-400">
              Any public GitHub repo with an MCP server
            </p>
          </div>
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-5 text-center">
            <div className="text-2xl mb-3">2</div>
            <h3 className="font-semibold text-slate-200 mb-1">Auto-scan</h3>
            <p className="text-xs text-slate-400">
              22 rules check for eval, path traversal, CORS, SSL bypass, injection
            </p>
          </div>
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-5 text-center">
            <div className="text-2xl mb-3">3</div>
            <h3 className="font-semibold text-slate-200 mb-1">Get score</h3>
            <p className="text-xs text-slate-400">
              0-100 vulnerability score with shareable results
            </p>
          </div>
        </div>
      </div>

      {/* What we detect */}
      <div className="w-full max-w-3xl mt-16">
        <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-slate-500 mb-8">
          What we detect
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs">
          {[
            'eval() / exec()',
            'Path traversal',
            'CORS wildcards',
            'SSL/TLS bypass',
            'SQL injection',
            'pickle / YAML load',
            'Insecure random',
            'Missing headers',
            'exec.Command sh -c',
            'Template injection',
            'npm lifecycle hooks',
            'Unpinned git deps',
          ].map((item) => (
            <div
              key={item}
              className="rounded-md border border-mcp-border bg-mcp-card px-3 py-2 text-slate-300"
            >
              {item}
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="w-full max-w-2xl mt-16 rounded-xl border border-mcp-accent/20 bg-mcp-accent/5 p-8 text-center">
        <h2 className="text-lg font-bold text-slate-200 mb-2">Need deeper analysis?</h2>
        <p className="text-sm text-slate-400 mb-4">
          This scanner covers L0-L1 (Discovery + Sandboxing). Production MCP servers need
          L2-L4: authorization, tool integrity, runtime monitoring.
        </p>
        <p className="text-xs text-slate-500 mb-4">
          49 rules. OWASP Top 10 (10/10). NIS2 Art. 21 (7/7). GDPR (6/6). DORA.
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
