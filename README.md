# compuute-scan

**Static security scanner for MCP servers. Zero dependencies. OWASP LLM Top 10 + NIS2 mapped.**

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#testing)

---

## What It Does

`compuute-scan` analyzes MCP (Model Context Protocol) server source code for security vulnerabilities before deployment. It runs fully offline, requires no API keys, and produces audit-ready reports mapped to **OWASP LLM Top 10**, **NIS2 Art. 21**, and **DORA** compliance frameworks.

## Quick Start

```bash
npx compuute-scan ./path/to/mcp-server
```

Or with Docker isolation (recommended for client code):

```bash
git clone https://github.com/Compuute/compuute-scan.git
cd compuute-scan
docker compose build
./scan.sh clone https://github.com/org/mcp-server.git
./scan.sh run mcp-server --output audit-report.md
```

## Installation

```bash
# npm (global)
npm install -g compuute-scan

# npx (no install)
npx compuute-scan ./mcp-server

# Docker (isolated scanning)
git clone https://github.com/Compuute/compuute-scan.git
cd compuute-scan
docker compose build
```

**Requirements:** Node.js 18+. No `npm install` needed — zero external dependencies.

## What It Scans

**23 rules across 5 VIGIL security layers:**

| Layer | Focus | Rules | Examples |
|-------|-------|-------|----------|
| **L0** | Discovery | Metadata | Transport detection, tool inventory, dependency pinning |
| **L1** | Sandboxing | 8 | `eval()`, `child_process`, path traversal, `0.0.0.0` binding |
| **L2** | Authorization | 4 | Hardcoded secrets, JWT expiry, missing auth/RBAC |
| **L3** | Tool Integrity | 6 | SSRF, SQL injection, JSON serialization leaks, input validation |
| **L4** | Monitoring | 5 | Missing audit logs, rate limiting, error information leakage |

### Guard Detection

The scanner checks a **±15-line window** around each finding for mitigation patterns (`validatePath()`, `sanitize()`, `realpath()`, etc.). Mitigated findings remain in the report with severity downgraded by one level — nothing is hidden, but noise is reduced.

### Negative Checks

Detects the **absence** of security controls across the entire codebase: no authentication, no RBAC, no audit logging, no rate limiting. Architectural risks that pattern matching alone won't catch.

## Example: Official MCP Servers Audit

Scan of [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) — 77 files:

| Severity | Raw Findings | After Validation |
|----------|-------------|-----------------|
| 🔴 Critical | 1 | 0 |
| 🟠 High | 63 | 2 confirmed |
| 🟡 Medium | 68 | 4 |
| 🟢 Low | 6 | 7 |
| **Total** | **138** | **13** |
| Mitigated by guard detection | 64 | — |

**Confirmed findings:**
- SSRF via unfiltered `fetch()` — no private IP blocking (cloud metadata harvesting)
- Full `process.env` dump exposing secrets to MCP clients

64 findings were automatically downgraded via guard detection. Manual review confirmed 125 false positives due to centralized validation patterns the scanner's window doesn't always reach — demonstrating where automated scanning ends and expert review begins.

## Docker-Isolated Scanning

For client engagements, `scan.sh` provides a hardened workflow where scanned code never touches the host filesystem:

```
┌──────────────┐         ┌──────────────────────┐
│  clone       │         │  scan                │
│  (git only)  │────────▶│  --network none      │
│  bridge net  │  volume │  read-only fs        │
└──────────────┘         │  cap_drop ALL        │
                         │  no-new-privileges   │
                         │  512MB / 1 CPU       │
                         └──────────────────────┘
```

| Property | Clone Container | Scan Container |
|----------|----------------|----------------|
| Network | Bridge (git only) | **none** — zero network stack |
| Filesystem | Read-only + tmpfs | **Read-only** |
| Capabilities | NET_RAW only | **All dropped** |
| User | Non-root (`scanner`) | Non-root (`scanner`) |
| Resources | 0.5 CPU, 256MB | 1 CPU, 512MB |

```bash
./scan.sh clone https://github.com/org/mcp-server.git   # Clone to isolated volume
./scan.sh run mcp-server --output audit.md               # Scan — zero network
./scan.sh local ~/code --output local-audit.md           # Scan local dir (mounted :ro)
./scan.sh list                                            # List cloned repos
./scan.sh clean mcp-server                                # Remove client code
```

## CLI Options

```
compuute-scan <path> [options]

  --output, -o <file>     Write report to file (Markdown)
  --json                  Output as JSON (for CI integration)
  --layer <L0-L4>         Filter by VIGIL layer
  --min-severity <level>  Filter by minimum severity (critical|high|medium|low)
  --verbose               Show files being scanned
  --help, -h              Show help
```

## Adding Rules

Rules are defined as objects in `compuute-scan.js`:

```javascript
{
  id: 'L1-009',
  title: 'Description',
  layer: 'L1',
  severity: 'high',
  owasp: 'A03:2021 Injection',
  nis2: 'Art. 21(2)(e)',
  description: 'What the rule detects',
  recommendation: 'How to fix it',
  test: (line) => /pattern/.test(line),
  guards: [/mitigationPattern/],
}
```

## Testing

```bash
npm test
```

The test suite validates detection accuracy against 9 purpose-built vulnerable MCP servers covering all VIGIL layers.

## License

MIT

## Contact

**Compuute AB** — Agentic AI Security
daniel@compuute.se | [compuute.se](https://compuute.se)
