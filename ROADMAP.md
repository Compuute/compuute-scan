# compuute-scan — Roadmap

> Last updated: 2026-04-10

## Current State (v0.3.1)

### Open-Core Model

`compuute-scan` is open source with an open-core business model:

| Tier | Layers | Rules | Technology | What You Get |
|---|---|---|---|---|
| **Open Source** (this repo) | L0 + L1 | 22 | Pattern matching | Discovery, sandboxing, code execution risks |
| **[Compuute Professional Audit](https://compuute.se/audit)** | L0–L4 | 49 | **Knowledge graph + dataflow analysis** | Architecture-aware analysis, attack path visualization, OWASP/NIS2/GDPR/DORA compliance |

### The Difference

```
L0-L1 (Open Source)              L2-L4 (Professional Audit)
Pattern matching                 Knowledge graph-driven analysis
─────────────────                ──────────────────────────────
"eval(x) found on line 42"      "x originates from req.body.input,
                                  passes through transform() without
                                  sanitization, and reaches eval()
                                  → full RCE attack path"
```

Open source tells you **what** was found. Professional audit tells you **how it can be exploited**.

### Language Support

| Language | Ecosystem Share | Status | Availability |
|---|---|---|---|
| TypeScript/JavaScript | 40.4% | **Full** | Open Source |
| Python | 35.0% | **Full** | Open Source |
| Go | 6.2% | **Full** | Open Source |
| Rust | 3.3% | Planned | — |
| C# | 1.9% | Planned | — |
| Java/Kotlin | 2.0% | Planned | — |

### Compliance Coverage (Professional Audit)

| Framework | Coverage | Detail |
|---|---|---|
| **OWASP Top 10 (2021)** | **10/10** | All categories covered |
| **NIS2 Art. 21(2)** | **7/7 technical** | (a), (b), (i) are process/organisational — out of scope |
| **GDPR** | **6/6 technical** | Art. 5(1)(b)(c)(e)(f), Art. 25, Art. 32 |
| **DORA** | **4/7** | Art. 5-6, 8-9, 28. Remainder is process/runtime |

### Data-Driven Decisions

Based on ecosystem analysis (April 2026):

- **11,720** GitHub repos tagged `mcp-server`
- **97M+** combined SDK downloads (npm + PyPI)
- **38.7%** of MCP servers lack authentication (Bloomberry, n=1,400)
- **7.2%** contain general security vulnerabilities (arxiv 2506.13538, n=1,899)
- **5.5%** exhibit MCP-specific tool poisoning

---

## Completed Milestones

### v0.1.0 — Initial Release
- Core scanner with VIGIL 5-layer model
- 20 rules (L1-L4)
- Markdown output
- Docker-isolated scanning workflow

### v0.2.0 — CI/CD & Supply Chain
- 28 rules
- SARIF output (GitHub Code Scanning)
- `--fail-on-severity` for CI integration
- npm lifecycle hook detection
- Unpinned git dependency detection
- ReDoS pattern detection

### v0.3.0 — Open-Core Split, Python & Go Support
- **Open-core model**: L0-L1 open source, L2-L4 in Professional Audit
- **49 total rules** (22 open source, 27 professional)
- **Full Python support**: pickle, YAML unsafe load, f-string SQL injection, SSL bypass, insecure random, Starlette CORS
- **Full Go support**: exec.Command, template injection, sql.Exec with Sprintf, TLS skip, Go CORS wildcard
- **Enhanced L0 Discovery**: Python/Go transport detection, pyproject.toml/go.mod parsing, tool counting
- Upgrade CTA in markdown, JSON, and SARIF output

### v0.3.1 — Credibility & CI (current)
- **GitHub Actions CI**: Node 18/20/22 matrix, self-scan, integrity verification
- **Inline suppression**: `// compuute-scan-ignore-next-line [L1-006]`
- **Config file** (`.compuute-scan.json`): disable rules, override severity, ignore file patterns
- **Release automation**: npm publish with SHA-256 hash verification
- **Security audit**: 16 findings fixed (concurrent scan isolation, secret redaction, etc.)
- **Supply chain security**: `verify-integrity.js` + `SECURITY.md`
- 72 tests (up from 58)

---

## Planned (Open Source)

### v0.4.0 — Reach Expansion

**Goal:** More providers, fewer false positives, serverless deployment.

- [ ] **GitLab + Bitbucket support** in web UI (+30-35% addressable market)
- [ ] **Function-boundary-aware guards** — Scan entire function body, not just ±15 lines
- [ ] **Serverless-compatible web UI** — Deploy on Vercel without Docker
- [ ] **Persistent rate limiter** — Upstash Redis via REST API (zero npm deps)
- [ ] **100+ test assertions** — Per-rule positive/negative tests, self-scan

### v0.5.0 — Community & Content

**Goal:** Module split for contributors, Rust support, ecosystem research.

- [ ] **Module split** — `src/` directory with build step producing single-file output
- [ ] **Rust** support (3.3% ecosystem) — `unsafe {}`, `Command::new()`, SQL formatting
- [ ] **Ecosystem scan script** — Automated anonymous aggregate statistics for 50+ MCP servers
- [ ] **Blog post**: "We scanned 50 MCP servers. Here's what we found."

### v0.6.0 — Dependency & CVE Analysis

**Goal:** Close OWASP A06 (Vulnerable Components) gap.

- [ ] **Offline CVE matching** — Ship a compressed CVE database for top 1,000 npm/PyPI/Go packages
- [ ] **Dependency age check** — Flag dependencies not updated in >12 months
- [ ] **License compliance** — Flag copyleft licenses in commercial projects
- [ ] `go.sum` / `package-lock.json` / `poetry.lock` integrity verification
- [ ] **C#/.NET** support (1.9%) — `Process.Start()`, `SqlCommand` string concat, `[AllowAnonymous]`
- [ ] **Java/Kotlin** support (2.0%) — `Runtime.exec()`, JDBC string concat, Spring Security patterns

---

## Planned (Professional Audit)

### v1.0 — Knowledge Graph-Driven Security Analysis

**Goal:** Architecture-aware analysis that no competitor offers for MCP servers.

**What it is:**
While open-source compuute-scan uses pattern matching ("is there an eval() call?"), the professional audit builds a **knowledge graph** of the entire MCP server architecture:

- **Nodes**: functions, variables, API endpoints, tool definitions, data stores
- **Edges**: data flows, call chains, permission boundaries, trust zones
- **Queries**: "show me every path from user input to code execution"

**Capabilities:**

| Capability | Pattern Matching (L1) | Knowledge Graph (L2-L4) |
|---|---|---|
| Find `eval()` | Yes | Yes |
| Know if input reaches `eval()` | No | **Yes — full taint tracking** |
| Detect chained vulnerabilities | No | **Yes — A→B→C attack paths** |
| Visualize trust boundaries | No | **Yes — graph visualization** |
| Map to compliance frameworks | Basic | **Full — with evidence chains** |
| Understand MCP tool→handler flow | No | **Yes — tool registration to execution** |

**MCP-specific analysis:**
- **Tool registration graph**: Maps `server.tool()` registrations to their handler functions
- **Permission boundary analysis**: Which tools access filesystem/network/exec without authorization checks
- **Cross-tool data flow**: Can Tool A's output influence Tool B's behavior?
- **Prompt injection paths**: Can a tool response manipulate the LLM into calling dangerous tools?

**Architecture:**
```
compuute-scan (L0-L1)                    compuute-audit (L2-L4)
├── Pattern matching                     ├── Knowledge graph engine
├── Discovery data ──────────────────────→── Ingests findings + file structure
│   (files, tools, deps)                 ├── Builds function call graph
│                                        ├── Traces data flows (taint analysis)
│                                        ├── Detects chained vulnerabilities
│                                        ├── Generates attack path visualizations
│                                        └── Maps to OWASP/NIS2/GDPR/DORA with evidence
```

**Differentiering vs. konkurrenter:**
- **Semgrep/CodeQL**: AST-based pattern matching — finds individual vulnerabilities, not attack chains
- **Snyk**: Dependency-focused — doesn't analyze custom MCP tool code
- **compuute-audit**: Knowledge graph-driven — traces full attack paths through MCP architecture

**This is the upgrade path:** L0-L1 scan shows you have vulnerabilities. L2-L4 audit shows you exactly how they can be exploited, with visual attack paths and compliance evidence chains.

### Continuous Enhancement
- Expanded L2-L4 rule coverage for new frameworks and patterns
- Full compliance report generation (OWASP, NIS2, GDPR, DORA) with evidence chains
- Multi-repo batch scanning for enterprise customers
- Baseline/diff mode — only report new findings since last scan
- Attack path export (PDF, interactive HTML)

---

## Out of Scope (by design)

These are organisational/process requirements that a static code scanner cannot and should not address:

| Requirement | Framework | Why out of scope |
|---|---|---|
| Risk analysis & IS policy | NIS2 Art. 21(2)(a) | Organisational process |
| Incident handling procedures | NIS2 Art. 21(2)(b) | Organisational process |
| Personnel security | NIS2 Art. 21(2)(i) | HR process |
| MFA / secure communication | NIS2 Art. 21(2)(j) | Runtime/infrastructure |
| Incident reporting | GDPR Art. 33-34 | Organisational process |
| Data Protection Impact Assessment | GDPR Art. 35 | Organisational process |
| Records of processing | GDPR Art. 30 | Organisational process |
| ICT asset identification | DORA Art. 7 | Asset management process |
| Incident management | DORA Art. 10 | Organisational process |
| Recovery & continuity | DORA Art. 11 | Infrastructure/process |

---

## Contributing

Rules are defined as plain objects in `compuute-scan.js`. See the "Adding Rules" section in README.md.

**Compuute AB** — Agentic AI Security
daniel@compuute.se | [compuute.se](https://compuute.se)
