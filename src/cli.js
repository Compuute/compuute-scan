// ─────────────────────────────────────────────
// CLI Argument Parsing
// ─────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    repoPath: null,
    output: null,
    json: false,
    sarif: false,
    verbose: false,
    layer: null,    // filter by layer e.g. "L1"
    minSeverity: null,
    failOnSeverity: null,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--help' || a === '-h') { opts.help = true; }
    else if (a === '--json') { opts.json = true; }
    else if (a === '--sarif') { opts.sarif = true; }
    else if (a === '--verbose' || a === '-v') { opts.verbose = true; }
    else if (a === '--output' || a === '-o') { opts.output = args[++i]; }
    else if (a === '--layer') { opts.layer = args[++i]?.toUpperCase(); }
    else if (a === '--min-severity') { opts.minSeverity = args[++i]?.toLowerCase(); }
    else if (a === '--fail-on-severity') { opts.failOnSeverity = args[++i]?.toLowerCase(); }
    else if (!a.startsWith('-')) { opts.repoPath = a; }
  }

  return opts;
}

function printUsage() {
  console.log(`
compuute-scan v${VERSION} — MCP Server Security Scanner
Compuute AB | Internal Tool

Usage:
  compuute-scan <repo-path> [options]

Options:
  --output <file>         Write report to file
  --json                  Output JSON instead of markdown
  --sarif                 Output SARIF (GitHub Code Scanning)
  --verbose               Show files being scanned
  --layer <L0-L4>         Filter findings by layer
  --min-severity <s>      Filter: critical, high, medium, low
  --fail-on-severity <s>  Exit code 1 if findings >= severity (for CI)
  --help                  Show this message

Exit codes:
  0  No findings (or below --fail-on-severity threshold)
  1  Findings at or above --fail-on-severity threshold
  2  Scanner error (invalid path, etc.)

Examples:
  compuute-scan ./my-mcp-server
  compuute-scan ./server --output report.md
  compuute-scan ./server --json --output report.json
  compuute-scan ./server --sarif --output report.sarif
  compuute-scan ./server --layer L1 --min-severity high
  compuute-scan ./server --fail-on-severity high
`);
}
