export default function About() {
  return (
    <div className="max-w-2xl mx-auto space-y-10">
      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-4">About Death by MCP</h1>
        <p className="text-slate-400 leading-relaxed">
          <strong className="text-slate-200">Death by MCP</strong> is a free tool that scans
          MCP (Model Context Protocol) servers for security vulnerabilities. Paste a GitHub
          repo URL and get a vulnerability score in 30 seconds.
        </p>
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">Why MCP security matters</h2>
        <p className="text-slate-400 leading-relaxed mb-3">
          MCP servers give AI agents direct access to tools, filesystems, databases, and
          APIs. A vulnerable MCP server can lead to:
        </p>
        <ul className="space-y-2 text-sm text-slate-400">
          <li className="flex gap-2">
            <span className="text-mcp-red">*</span>
            <span>Remote code execution via eval(), exec(), or pickle deserialization</span>
          </li>
          <li className="flex gap-2">
            <span className="text-mcp-red">*</span>
            <span>Path traversal allowing file system access beyond intended scope</span>
          </li>
          <li className="flex gap-2">
            <span className="text-mcp-red">*</span>
            <span>SSRF attacks harvesting cloud metadata and internal services</span>
          </li>
          <li className="flex gap-2">
            <span className="text-mcp-red">*</span>
            <span>SQL injection through unsanitized tool inputs</span>
          </li>
          <li className="flex gap-2">
            <span className="text-mcp-red">*</span>
            <span>Prompt injection via poisoned tool metadata</span>
          </li>
        </ul>
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">The scanner</h2>
        <p className="text-slate-400 leading-relaxed mb-3">
          This tool runs{' '}
          <a
            href="https://github.com/Compuute/compuute-scan"
            className="text-mcp-accent hover:underline"
          >
            compuute-scan
          </a>{' '}
          v0.3.0 &mdash; an open-source static security scanner built specifically for MCP
          servers. Zero dependencies. Runs offline.
        </p>

        <div className="rounded-lg border border-mcp-border bg-mcp-card p-5 text-sm">
          <table className="w-full">
            <tbody className="divide-y divide-mcp-border">
              <tr>
                <td className="py-2 text-slate-500">Languages</td>
                <td className="py-2 text-slate-200">TypeScript, JavaScript, Python, Go</td>
              </tr>
              <tr>
                <td className="py-2 text-slate-500">Ecosystem coverage</td>
                <td className="py-2 text-slate-200">81% (11,720+ repos analyzed)</td>
              </tr>
              <tr>
                <td className="py-2 text-slate-500">Rules (this tool)</td>
                <td className="py-2 text-slate-200">22 (L0 Discovery + L1 Sandboxing)</td>
              </tr>
              <tr>
                <td className="py-2 text-slate-500">Rules (full audit)</td>
                <td className="py-2 text-slate-200">49 (L0-L4 all layers)</td>
              </tr>
              <tr>
                <td className="py-2 text-slate-500">Compliance</td>
                <td className="py-2 text-slate-200">
                  OWASP (10/10), NIS2 (7/7), GDPR (6/6), DORA (4/7)
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">Compuute's 5-layer security framework</h2>
        <div className="rounded-lg border border-mcp-border bg-mcp-card overflow-hidden text-sm">
          <table className="w-full">
            <thead>
              <tr className="border-b border-mcp-border text-xs text-slate-500 uppercase">
                <th className="px-4 py-3 text-left">Layer</th>
                <th className="px-4 py-3 text-left">Focus</th>
                <th className="px-4 py-3 text-left">Availability</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-mcp-border">
              <tr>
                <td className="px-4 py-3 text-mcp-accent font-semibold">L0</td>
                <td className="px-4 py-3 text-slate-200">Discovery</td>
                <td className="px-4 py-3 text-mcp-green">Open Source</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-mcp-accent font-semibold">L1</td>
                <td className="px-4 py-3 text-slate-200">Sandboxing</td>
                <td className="px-4 py-3 text-mcp-green">Open Source</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-mcp-accent font-semibold">L2</td>
                <td className="px-4 py-3 text-slate-200">Authorization</td>
                <td className="px-4 py-3 text-slate-400">Professional Audit</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-mcp-accent font-semibold">L3</td>
                <td className="px-4 py-3 text-slate-200">Tool Integrity</td>
                <td className="px-4 py-3 text-slate-400">Professional Audit</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-mcp-accent font-semibold">L4</td>
                <td className="px-4 py-3 text-slate-200">Monitoring</td>
                <td className="px-4 py-3 text-slate-400">Professional Audit</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">Ecosystem data</h2>
        <p className="text-slate-400 leading-relaxed mb-3">
          Based on analysis of the MCP server ecosystem (April 2026):
        </p>
        <div className="grid grid-cols-2 gap-3 text-center">
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-4">
            <div className="text-2xl font-bold text-slate-200">11,720+</div>
            <div className="text-xs text-slate-500">GitHub repos</div>
          </div>
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-4">
            <div className="text-2xl font-bold text-slate-200">97M+</div>
            <div className="text-xs text-slate-500">SDK downloads</div>
          </div>
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-4">
            <div className="text-2xl font-bold text-mcp-red">38.7%</div>
            <div className="text-xs text-slate-500">lack authentication</div>
          </div>
          <div className="rounded-lg border border-mcp-border bg-mcp-card p-4">
            <div className="text-2xl font-bold text-mcp-orange">7.2%</div>
            <div className="text-xs text-slate-500">have vulnerabilities</div>
          </div>
        </div>
      </div>

      <div id="responsible-disclosure">
        <h2 className="text-xl font-bold mb-3">Responsible disclosure policy</h2>
        <p className="text-slate-400 leading-relaxed mb-3">
          We take security ethics seriously. Death by MCP is designed as a
          self-service tool for developers to scan <strong className="text-slate-200">their own</strong> code.
        </p>
        <div className="rounded-lg border border-mcp-border bg-mcp-card p-5 text-sm space-y-3">
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">Consent required</h3>
            <p className="text-slate-400">
              Users must confirm ownership or permission before scanning. We do not
              scan repositories without the owner&apos;s knowledge.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">No public exposure</h3>
            <p className="text-slate-400">
              Scan results are shown only to the user who initiated the scan. Results
              are not indexed, stored, or shared publicly by us. Sharing is opt-in and
              at the user&apos;s discretion.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">Credential redaction</h3>
            <p className="text-slate-400">
              Any secrets, API keys, credentials, email addresses, or connection strings
              found in scan output are automatically redacted before display.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">No code retention</h3>
            <p className="text-slate-400">
              Cloned repositories are deleted immediately after scanning. No source code
              is retained on our servers.
            </p>
          </div>
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">Aggregated research</h3>
            <p className="text-slate-400">
              Any ecosystem research we publish uses only aggregated, anonymized statistics
              (e.g. &quot;75% of MCP servers had at least one finding&quot;). We never name
              specific repositories or maintainers in public reports without explicit consent.
            </p>
          </div>
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold mb-3">Security contact</h2>
        <p className="text-slate-400 leading-relaxed">
          If you believe your repository was scanned without authorization, or if you have
          security concerns about this tool, contact us at{' '}
          <a href="mailto:daniel@compuute.se" className="text-mcp-accent hover:underline">
            daniel@compuute.se
          </a>.
        </p>
      </div>

      {/* CTA */}
      <div className="rounded-xl border border-mcp-accent/20 bg-mcp-accent/5 p-8 text-center">
        <h2 className="text-lg font-bold text-slate-200 mb-2">Full security assessment</h2>
        <p className="text-sm text-slate-400 mb-4">
          49 rules across 5 layers. OWASP Top 10 (10/10). NIS2 (7/7). GDPR (6/6). DORA.
          Audit-ready compliance reports.
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

      <div className="text-center text-sm text-slate-500">
        <p>
          <strong className="text-slate-400">Compuute AB</strong> &mdash; Agentic AI Security
        </p>
        <p className="mt-1">daniel@compuute.se | compuute.se</p>
      </div>
    </div>
  );
}
