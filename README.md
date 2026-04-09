# compuute-scan

**Static security scanner for MCP servers. Covers 81% of the MCP ecosystem (TypeScript, JavaScript, Python, Go). Zero dependencies. OWASP Top 10 + NIS2 + GDPR + DORA mapped.**

[![Version](https://img.shields.io/badge/version-0.3.0-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![CI](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml)

---

## What It Does

`compuute-scan` analyzes MCP (Model Context Protocol) server source code for security vulnerabilities before deployment. It runs fully offline, requires no API keys, and produces audit-ready reports mapped to **OWASP Top 10 (2021)**, **NIS2 Art. 21**, **GDPR Art. 5/25**, and **DORA** compliance frameworks.

**Supports TypeScript, JavaScript, Python, and Go** — covering ~81% of the MCP server ecosystem (based on 11,720+ GitHub repos, April 2026).

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

**49 rules across 5 VIGIL security layers:**

| Layer | Focus | Rules | Examples |
|-------|-------|-------|----------|
| **L0** | Discovery | Metadata | Transport detection (stdio/SSE/HTTP), tool inventory, dependency pinning, go.mod/pyproject.toml parsing |
| **L1** | Sandboxing | 22 | `eval()`, `exec.Command`, `pickle.loads`, `yaml.load`, path traversal, CORS wildcards, SSL bypass, insecure random |
| **L2** | Authorization | 11 | Hardcoded secrets/DB strings, JWT expiry/verify bypass, missing auth/RBAC, PII storage/logging, weak crypto (MD5/SHA1), data retention |
| **L3** | Tool Integrity | 10 | SSRF, SQL injection (JS/Python f-string/Go fmt.Sprintf), prompt injection, PII in responses, supply chain |
| **L4** | Monitoring | 6 | Missing audit logs, rate limiting, error leakage, ReDoS patterns |

### Language-Specific Rules

| Language | Ecosystem Share | Key Detections |
|---|---|---|
| **TypeScript/JS** | 40% | eval, child_process, CORS, SSRF, npm hooks, unpinned git deps |
| **Python** | 35% | pickle, YAML unsafe load, f-string SQL injection, Starlette CORS, hashlib, verify=False |
| **Go** | 6% | exec.Command+sh, fmt.Sprintf SQL, InsecureSkipVerify, text/template XSS, rs/cors wildcard |

### Compliance Coverage

| Framework | Coverage |
|---|---|
| **OWASP Top 10 (2021)** | **10/10** — all categories |
| **NIS2 Art. 21(2)** | **7/7** technical (a/b/i are organisational) |
| **GDPR** | **6/6** technical — Art. 5(1)(b)(c)(e)(f), Art. 25, Art. 32 |
| **DORA** | **4/7** — Art. 5-6, 8-9, 28 (remainder is process/runtime) |

### Guard Detection

The scanner checks a **±15-line window** around each finding for mitigation patterns (`validatePath()`, `sanitize()`, `realpath()`, etc.). Mitigated findings remain in the report with severity downgraded by one level — nothing is hidden, but noise is reduced.

### Negative Checks

Detects the **absence** of security controls across the entire codebase: no authentication, no RBAC, no PII redaction, no input validation (zod/pydantic), no security headers (helmet), no audit logging, no rate limiting. Architectural risks that pattern matching alone won't catch.

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

  --output, -o <file>        Write report to file
  --json                     Output as JSON
  --sarif                    Output as SARIF (GitHub Code Scanning)
  --layer <L0-L4>            Filter by VIGIL layer
  --min-severity <level>     Filter: critical, high, medium, low
  --fail-on-severity <level> Exit code 1 if findings >= severity (for CI)
  --verbose                  Show files being scanned
  --help, -h                 Show help
```

### CI Integration

```yaml
# GitHub Actions example
- run: npx compuute-scan ./src --fail-on-severity high --sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Adding Rules

Rules are defined as objects in `compuute-scan.js`:

```javascript
{
  id: 'L1-010',
  title: 'Description',
  layer: 'L1',
  severity: 'high',
  owasp: 'A03:2021 Injection',
  nis2: 'Art. 21(2)(e)',
  gdpr: 'Art. 5(1)(c) — Data minimisation',  // optional
  dora: 'Art. 6(8) — Data integrity',         // optional
  description: 'What the rule detects',
  recommendation: 'How to fix it',
  test: (line) => /pattern/.test(line),
  guards: [/mitigationPattern/],
}
```

See [ROADMAP.md](ROADMAP.md) for planned features and language support timeline.
```

## Testing

```bash
npm test
```

The test suite validates detection accuracy against 9 purpose-built vulnerable MCP servers covering all VIGIL layers.

## License

MIT — see [LICENSE](LICENSE).

## Contact

**Compuute AB** — Agentic AI Security
daniel@compuute.se | [compuute.se](https://compuute.se)
