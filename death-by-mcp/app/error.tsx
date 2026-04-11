'use client';

export default function Error({ reset }: { reset: () => void }) {
  return (
    <div className="text-center py-24">
      <h1 className="text-2xl font-bold text-slate-200 mb-4">Something went wrong</h1>
      <p className="text-slate-400 mb-6">
        An unexpected error occurred. Please try again.
      </p>
      <div className="flex justify-center gap-4">
        <button
          onClick={reset}
          className="rounded-lg bg-mcp-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 transition-colors"
        >
          Try again
        </button>
        <a
          href="/"
          className="rounded-lg border border-mcp-border bg-mcp-card px-6 py-2.5 text-sm text-slate-300 hover:bg-white/[0.03] transition-colors"
        >
          Back to home
        </a>
      </div>
    </div>
  );
}
