# compuute-scan

**Open-source security scanner for MCP servers. Detects sandboxing & code execution risks across TypeScript, JavaScript, Python, and Go (81% of the MCP ecosystem). Zero dependencies.**

[![Version](https://img.shields.io/badge/version-0.3.0-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![CI](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml)

---

## What It Does

`compuute-scan` analyzes MCP (Model Context Protocol) server source code for security vulnerabilities before deployment. It runs fully offline, requires no API keys, and covers **L0 Discovery** and **L1 Sandboxing** — the foundational security layers every MCP server needs.

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

### VIGIL Security Layers

| Layer | Focus | Availability |
|-------|-------|-------------|
| **L0** | Discovery — transport detection, tool inventory, dependency pinning | Open Source |
| **L1** | Sandboxing — `eval()`, `exec.Command`, `pickle.loads`, path traversal, CORS, SSL bypass | Open Source |
| **L2** | Authorization — RBAC, secrets, JWT, PII/GDPR, crypto | [Compuute Professional Audit](https://compuute.se/audit) |
| **L3** | Tool Integrity — SSRF, SQL injection, prompt injection, supply chain | [Compuute Professional Audit](https://compuute.se/audit) |
| **L4** | Monitoring — audit logging, rate limiting, error leakage, ReDoS | [Compuute Professional Audit](https://compuute.se/audit) |

### Open Source Rules (L0 + L1)

**22 rules** covering code execution, sandboxing, and discovery:

| Category | Examples |
|----------|----------|
| **Code execution** | `eval()`, `exec.Command`, `pickle.loads`, `yaml.load(Loader=FullLoader)` |
| **Path traversal** | Unsanitized file paths, missing `realpath()` checks |
| **CORS misconfiguration** | Wildcard origins in cors(), Starlette, rs/cors |
| **SSL/TLS bypass** | `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify` |
| **SQL injection** | Python f-string queries, Go `fmt.Sprintf` queries |
| **Insecure random** | `Math.random()`, `random.choices()`, `rand.Intn()` for security |
| **Template injection** | Go `text/template` for HTML output |
| **Security headers** | Missing helmet/secure-headers middleware |
| **Discovery** | Transport detection, tool inventory, dependency pinning, go.mod/pyproject.toml parsing |

### Language-Specific Rules

| Language | Ecosystem Share | Key Detections |
|---|---|---|
| **TypeScript/JS** | 40% | eval, child_process, CORS, npm hooks, unpinned git deps |
| **Python** | 35% | pickle, YAML unsafe load, f-string SQL, Starlette CORS, verify=False |
| **Go** | 6% | exec.Command+sh, fmt.Sprintf SQL, InsecureSkipVerify, text/template XSS, rs/cors |

### Guard Detection

The scanner checks a **±15-line window** around each finding for mitigation patterns (`validatePath()`, `sanitize()`, `realpath()`, etc.). Mitigated findings remain in the report with severity downgraded by one level — nothing is hidden, but noise is reduced.

### Negative Checks

Detects the **absence** of security controls across the entire codebase: no input validation (zod/pydantic), no security headers (helmet). Architectural risks that pattern matching alone won't catch.

## Full Security Assessment

The open-source scanner covers foundational L0-L1 risks. Production MCP deployments need deeper analysis:

| Layer | What You Get | Rules |
|-------|-------------|-------|
| **L2 Authorization** | RBAC, secret management, JWT/OAuth, PII/GDPR compliance, weak crypto | 11 |
| **L3 Tool Integrity** | SSRF, injection, prompt poisoning, PII in responses, supply chain | 10 |
| **L4 Runtime Monitoring** | Audit logging, rate limiting, error leakage, ReDoS | 6 |

**49 rules total. OWASP Top 10 (10/10). NIS2 Art. 21 (7/7). GDPR (6/6). DORA (4/7).**

> **[Book a Compuute Professional Audit](https://compuute.se/audit)** — full L0-L4 assessment with compliance mapping for OWASP, NIS2, GDPR, and DORA.

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
  --layer <L0-L1>            Filter by VIGIL layer
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
  description: 'What the rule detects',
  recommendation: 'How to fix it',
  test: (line) => /pattern/.test(line),
  guards: [/mitigationPattern/],
}
```

See [ROADMAP.md](ROADMAP.md) for planned features and language support timeline.

## Testing

```bash
npm test
```

The test suite validates detection accuracy against purpose-built vulnerable MCP servers.

## License

MIT — see [LICENSE](LICENSE).

## Contact

**Compuute AB** — Agentic AI Security
daniel@compuute.se | [compuute.se](https://compuute.se)
