# compuute-scan — Roadmap

> Last updated: 2026-04-09

## Current State (v0.3.0)

**49 security rules** across 5 VIGIL layers, covering **~81% of the MCP ecosystem** by language.

### Language Support

| Language | Ecosystem Share | Status | Rules |
|---|---|---|---|
| TypeScript/JavaScript | 40.4% | **Full** | All 42 rules apply |
| Python | 35.0% | **Full** | 10 Python-specific rules + all general rules |
| Go | 6.2% | **Full** | Go-specific rules + all general rules |
| Rust | 3.3% | Planned | — |
| C# | 1.9% | Planned | — |
| Java/Kotlin | 2.0% | Planned | — |

### Compliance Coverage

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

### v0.3.0 — PII/GDPR, Python & Go Support (current)
- **49 rules** (21 new)
- **PII/GDPR rules**: L2-005 (PII storage), L2-006 (PII logging), L2-007 (no PII mechanism), L3-010 (PII in tool responses)
- **Compliance gap closure**: OWASP A02 (crypto), A05 (CORS/headers), GDPR Art. 5(1)(e) (retention)
- **Full Python support**: pickle, YAML unsafe load, f-string SQL injection, SSL bypass, insecure random, Starlette CORS, hardcoded DB strings, JWT verify bypass
- **Full Go support**: exec.Command, template injection, sql.Exec with Sprintf, TLS skip, hardcoded secrets, Go CORS wildcard
- **Enhanced L0 Discovery**: Python/Go transport detection, pyproject.toml/go.mod parsing, tool counting for FastMCP/@mcp.tool/Go handlers
- GDPR (Art. 5, 25) and DORA (Art. 6) mappings on all PII/data rules

---

## Planned

### v0.4.0 — Enhanced Detection Quality

**Goal:** Reduce false positives, increase true positives.

- [ ] **Cross-file taint tracking** — Follow data flow from tool input to dangerous sink across files
- [ ] **Configurable rule sets** — `.compuute-scan.yml` to enable/disable rules, set custom severity
- [ ] **Ignore comments** — `// compuute-scan-ignore-next-line` / `# noqa: L1-001`
- [ ] **Expanded guard window** — Configurable guard context (currently ±15 lines)
- [ ] **Call-graph-aware guards** — Detect guards in called functions, not just nearby lines

### v0.5.0 — Tier 3 Language Support

**Goal:** Reach 87%+ ecosystem coverage.

- [ ] **Rust** support (3.3% ecosystem) — `unsafe {}`, `Command::new()`, SQL formatting
- [ ] **C#/.NET** support (1.9%) — `Process.Start()`, `SqlCommand` string concat, `[AllowAnonymous]`
- [ ] **Java/Kotlin** support (2.0%) — `Runtime.exec()`, JDBC string concat, Spring Security patterns

### v0.6.0 — Dependency & CVE Analysis

**Goal:** Close OWASP A06 (Vulnerable Components) gap.

- [ ] **Offline CVE matching** — Ship a compressed CVE database for top 1,000 npm/PyPI/Go packages
- [ ] **Dependency age check** — Flag dependencies not updated in >12 months
- [ ] **License compliance** — Flag copyleft licenses in commercial projects
- [ ] `go.sum` / `package-lock.json` / `poetry.lock` integrity verification

### v0.7.0 — Enterprise & SaaS

- [ ] **Multi-repo batch scanning** — Scan a GitHub org's MCP servers in one run
- [ ] **Baseline/diff mode** — Only report new findings since last scan
- [ ] **HTML report** with interactive severity filtering
- [ ] **API mode** — Run as HTTP service for integration with security dashboards
- [ ] **Custom compliance frameworks** — Define your own mappings beyond OWASP/NIS2/GDPR/DORA

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
