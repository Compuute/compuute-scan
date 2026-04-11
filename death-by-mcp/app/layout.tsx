import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Death by MCP — How secure is your MCP server?',
  description:
    'Paste a GitHub repo URL, get a security score in 30 seconds. Supports TypeScript, JavaScript, Python, and Go. Powered by compuute-scan.',
  openGraph: {
    title: 'Death by MCP',
    description: 'How secure is your MCP server? Find out in 30 seconds.',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-mcp-bg text-slate-200 antialiased">
        <nav className="border-b border-mcp-border">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
            <a href="/" className="text-lg font-bold tracking-tight">
              <span className="text-mcp-red">Death</span>
              <span className="text-slate-400"> by </span>
              <span className="text-mcp-accent">MCP</span>
            </a>
            <div className="flex items-center gap-6 text-sm text-slate-400">
              <a href="/about" className="hover:text-slate-200 transition-colors">
                About
              </a>
              <a
                href="https://github.com/Compuute/compuute-scan"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-slate-200 transition-colors"
              >
                GitHub
              </a>
              <a
                href="https://compuute.se/audit"
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md bg-mcp-accent/10 px-3 py-1.5 text-mcp-accent hover:bg-mcp-accent/20 transition-colors"
              >
                Full Audit
              </a>
            </div>
          </div>
        </nav>

        <main className="mx-auto max-w-5xl px-6 py-12">{children}</main>

        <footer className="border-t border-mcp-border mt-24">
          <div className="mx-auto max-w-5xl px-6 py-8 text-center text-sm text-slate-500">
            <p>
              Powered by{' '}
              <a
                href="https://github.com/Compuute/compuute-scan"
                className="text-slate-400 hover:text-slate-200"
              >
                compuute-scan
              </a>{' '}
              v0.3.0 &mdash; 22 open-source rules (L0-L1)
            </p>
            <p className="mt-1">
              <a href="https://compuute.se" className="text-slate-400 hover:text-slate-200">
                Compuute AB
              </a>{' '}
              &mdash; Agentic AI Security
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
