# compuute-scan

**Open-source static security scanner for MCP servers. Detects sandboxing, code execution, dependency and supply-chain risks in TypeScript, JavaScript, Python, Go, Rust, C#, Java and Kotlin servers. Zero dependencies.**

[![Version](https://img.shields.io/badge/version-0.6.2-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![CI](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Compuute/compuute-scan/actions/workflows/ci.yml)

> **v0.6.2 adds .NET, Java and Kotlin support**, following the release of the official [Microsoft MCP C# SDK v1.0](https://devblogs.microsoft.com/dotnet/release-v10-of-the-official-mcp-csharp-sdk/) (March 2026) and the Java/Spring MCP SDK.

---

## What It Does

`compuute-scan` analyzes MCP (Model Context Protocol) server source code for security vulnerabilities before deployment. It runs fully offline, requires no API keys, and covers **L0 Discovery**, **L1 Sandboxing**, and **dependency-level risks** — the foundational security layers every MCP server needs.

**Languages:** TypeScript, JavaScript, Python, Go, Rust, C#, Java and Kotlin (Kotlin via the Java SDK). Aligned with the MCP 2025-11-25 specification.

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
| **L2** | Authorization — RBAC, secrets, JWT, PII/GDPR, crypto | Professional audit |
| **L3** | Tool Integrity — SSRF, SQL injection, prompt injection, supply chain | Professional audit |
| **L4** | Monitoring — audit logging, rate limiting, error leakage, ReDoS | Professional audit |

### Open Source Rules (L0 + L1)

**37 per-file rules + 2 negative rules + 3 dependency checks** covering code execution, sandboxing, discovery, and supply chain:

| Category | Examples |
|----------|----------|
| **Code execution** | `eval()`, `exec.Command`, `pickle.loads`, `yaml.load`, `Runtime.exec`, `Process.Start` |
| **Deserialization** | `BinaryFormatter`, `ObjectInputStream`, `SoapFormatter` — banned .NET and Java sinks |
| **Path traversal** | Unsanitized file paths, missing `realpath()` checks |
| **CORS misconfiguration** | Wildcard origins across Express, Starlette, rs/cors, ASP.NET Core `AllowAnyOrigin`, Spring `@CrossOrigin` |
| **SSL/TLS bypass** | `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`, `danger_accept_invalid_certs` |
| **SQL injection** | Python f-string, Go `fmt.Sprintf`, Rust `format!()`, C# `SqlCommand`, Java JDBC string-concat |
| **Command injection** | Shell execution with untrusted input across all 8 languages |
| **Auth bypass** | C# `[AllowAnonymous]`, Spring `permitAll()` on sensitive endpoints |
| **Memory safety** | Rust `unsafe {}` blocks, missing `#[deny(unsafe_code)]` |
| **Insecure random** | `Math.random()`, `random.choices()`, `rand.Intn()` for security contexts |
| **Template injection** | Go `text/template` for HTML output |
| **Security headers** | Missing helmet/secure-headers middleware |
| **Known CVEs (offline)** | 40+ top npm/PyPI/Go packages with curated vulnerable version ranges |
| **Dependency age** | Packages two or more major versions behind current |
| **License compliance** | Copyleft licenses (GPL, AGPL, LGPL, SSPL) in `node_modules` |
| **Discovery** | Transport detection, tool inventory, dependency pinning across 8 package managers |

### Language-Specific Rules

| Language | MCP SDK Status | Key Detections |
|---|---|---|
| **TypeScript/JS** | Official (Anthropic) | `eval`, `child_process`, CORS, npm hooks, unpinned git deps |
| **Python** | Official (Anthropic) | `pickle`, YAML unsafe load, f-string SQL, Starlette CORS, `verify=False` |
| **Go** | Official | `exec.Command`+sh, `fmt.Sprintf` SQL, `InsecureSkipVerify`, `text/template` XSS, `rs/cors` |
| **Rust** | Official | `unsafe {}`, `Command::new` + `format!`, SQL via `format!`, `danger_accept_invalid_certs` |
| **C#/.NET** | **Official (Microsoft, March 2026)** | `Process.Start`, `SqlCommand` concat, `[AllowAnonymous]`, `BinaryFormatter`, `AllowAnyOrigin` |
| **Java** | **Official (Spring/Java)** | `Runtime.exec`, JDBC concat, `ObjectInputStream`, Spring `permitAll`, `@CrossOrigin(*)` |
| **Kotlin** | Via Java SDK | Same as Java — JDBC, ObjectInputStream, Spring Security |

### Parsed Dependency Files

`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `.csproj`, `pom.xml`, `build.gradle`, `build.gradle.kts`.

### Guard Detection

The scanner checks a **±15-line window** around each finding for mitigation patterns (`validatePath()`, `sanitize()`, `realpath()`, etc.). Mitigated findings remain in the report with severity downgraded by one level — nothing is hidden, but noise is reduced.

### Negative Checks

Detects the **absence** of security controls across the entire codebase: no input validation (zod/pydantic), no security headers (helmet). Architectural risks that pattern matching alone won't catch.

## Full Security Assessment

The open-source scanner covers foundational L0-L1 risks and dependency-level checks. Production MCP deployments — especially those subject to NIS2, DORA, or GDPR — need deeper analysis with cross-file taint tracking and compliance evidence:

| Layer | What You Get | Analysis |
|-------|-------------|----------|
| **L2 Authorization** | RBAC, secret management, JWT/OAuth, PII/GDPR compliance, weak crypto | Knowledge-graph driven |
| **L3 Tool Integrity** | SSRF, injection, prompt poisoning, PII in responses, supply chain | Taint tracking |
| **L4 Runtime Monitoring** | Audit logging, rate limiting, error leakage, ReDoS | Cross-file behavioral |

**Mapping, not certification.** Open-source findings are tagged with [OWASP Top 10 (2021)](https://owasp.org/Top10/) categories (for example `A03:2021 Injection`) and with NIS2 Art. 21 references. A tag means a rule exists for that category; it is not a compliance score. The open-source tier detects patterns by reading syntax. Reachability, attack-path tracing and compliance evidence belong to a manual audit.

A full L0–L4 assessment is available as a [professional audit](https://compuute.se/audit).

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

As of v0.5.0, the scanner is organized as modules under `src/` and concatenated into `compuute-scan.js` by `scripts/build.js`. Do not edit the top-level `compuute-scan.js` directly — it is generated output.

Rules live in `src/rules-l1.js` as objects:

```javascript
{
  id: 'L1-037',
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

Build and run tests:

```bash
npm run build      # regenerates compuute-scan.js from src/
npm test           # runs the 231-assertion suite
npm run verify     # runs the supply-chain integrity check
```

See [CHANGELOG.md](CHANGELOG.md) for release history and [ROADMAP.md](ROADMAP.md) for planned features.

## Testing

```bash
npm test
```

The test suite runs 231 assertions covering URL validation, scoring, credential redaction, rate limiting, inline-ignore handling, config loading, function-boundary detection, per-rule pattern matching for every rule, dependency CVE/age checks, and an end-to-end self-scan.

**Validation against a known-vulnerable lab:** `./test.sh` clones Appsecco's [vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) and checks that the scanner flags the intentionally vulnerable servers.

## License

MIT — see [LICENSE](LICENSE).

## Contact

**Compuute AB** — Agentic AI Security
daniel@compuute.se | [compuute.se](https://compuute.se)
