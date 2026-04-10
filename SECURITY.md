# Security Model

compuute-scan is a security tool that scans untrusted code. This document
describes how the scanner itself is hardened against supply chain attacks,
data leakage, and runtime exploitation.

## Threat Model

| Threat | Vector | Mitigation |
|--------|--------|------------|
| **Scanned repo attacks host** | Git hooks, symlinks, malicious code | Docker isolation, hooks disabled, symlinks skipped |
| **Supply chain trojan** | Malicious PR adds backdoor to scanner | Integrity verifier, zero deps, branch protection |
| **Secret leakage** | Scanner exposes secrets found in code | 6-pattern redaction on all output fields |
| **Concurrent scan collision** | Two scans corrupt each other's data | Unique Docker volume per scan |
| **Resource exhaustion** | Huge repo DoS | CPU/memory limits, file size cap, rate limiting |

## Architecture: Defense in Depth

### Layer 1 — Zero Dependencies

The scanner is a single file (`compuute-scan.js`) with **zero external
dependencies**. Only three Node.js built-in modules are used:

- `fs` — read source files
- `path` — resolve file paths
- `crypto` — hash generation for scan IDs

No `node_modules`. No npm packages. No transitive dependency tree to attack.

### Layer 2 — Static Analysis Only

The scanner **never executes** scanned code. It reads files as text and
applies regex pattern matching. There are no calls to:

- `eval()` / `new Function()`
- `child_process.exec()` / `spawn()`
- `require()` with variable arguments
- `fetch()` / `http` / `https`
- `process.env`

This can be verified at any time:

```bash
node verify-integrity.js --audit-only
```

### Layer 3 — Docker Isolation (Death by MCP web UI)

When running through the web UI, scans execute in a two-stage Docker pipeline:

**Stage 1: Clone** (has network for git only)
- `cap_drop: ALL`, `cap_add: NET_RAW`
- `read_only: true`
- `no-new-privileges: true`
- `core.hooksPath=/dev/null` — all git hooks disabled
- 256MB memory limit, 0.5 CPU
- Non-root user (`scanner`)

**Stage 2: Scan** (zero network access)
- `network_mode: "none"` — no outbound connections possible
- `cap_drop: ALL` — no capabilities
- `read_only: true` with read-only volume mount
- `no-new-privileges: true`
- 512MB memory limit, 1.0 CPU
- Non-root user (`scanner`)

Each scan creates a **unique Docker volume** (`scan-work-<random>`) to prevent
concurrent scan collisions. Volumes are cleaned up in a `finally` block, even
on failure.

### Layer 4 — Secret Redaction

All finding output fields are scrubbed before leaving the server:

| Field | Redacted |
|-------|----------|
| `description` | Yes |
| `recommendation` | Yes |
| `code` | Yes |
| `guardCode` | Yes |
| `file` | Stripped to last 2 path segments |

Six redaction patterns cover:
1. API key/secret/password/token assignments
2. Long base64-encoded strings
3. Stripe-style prefixed keys (`sk_live_*`, `pk_test_*`)
4. Email addresses
5. Database connection strings (mongodb, postgres, mysql, redis)
6. IPv4 addresses

### Layer 5 — File Walker Hardening

- **Symlinks skipped** — `entry.isSymbolicLink()` check prevents path traversal
  via symlinks pointing outside the repo
- **File size cap** — Files larger than 500KB are skipped
- **Extension whitelist** — Only `.ts`, `.js`, `.py`, `.mjs`, `.cjs`, `.tsx`,
  `.jsx`, `.go` are scanned
- **Directory exclusion** — `node_modules`, `.git`, `dist`, `build`, etc. skipped

### Layer 6 — Input Validation

- GitHub URL regex: `^https://github.com/[\w.-]+/[\w.-]+(\.git)?$`
- Maximum URL length: 200 characters
- Consent checkbox required (web UI)
- Rate limiting: 10 scans per IP per hour

## Integrity Verification

### For Users

Verify that your copy of the scanner hasn't been tampered with:

```bash
# Full check: hash + pattern audit
node verify-integrity.js --hash <expected-sha256>

# Pattern audit only (no hash comparison)
node verify-integrity.js --audit-only
```

The verifier checks that `compuute-scan.js`:
1. Matches the published SHA-256 hash for the release
2. Contains no `child_process`, `exec`, `spawn`, `eval`, `fetch`, or network calls
3. Has no unexpected `require()` statements (only `fs`, `path`, `crypto`)
4. Has no `process.env` access (can't leak environment secrets)
5. Has no dynamic `require()` with variable arguments

### For Contributors

Before each release:

```bash
# Generate hash for release notes
sha256sum compuute-scan.js

# Run integrity check
node verify-integrity.js

# Run unit tests
node death-by-mcp/test.js
```

Release notes must include the SHA-256 hash of `compuute-scan.js`.

## Reporting Vulnerabilities

If you discover a security vulnerability in compuute-scan, please report it
responsibly:

- **Email**: daniel@compuute.se
- **Subject**: `[SECURITY] compuute-scan — <brief description>`
- **Response time**: 48 hours acknowledgement, 90-day disclosure window

Do not open a public GitHub issue for security vulnerabilities.

## What This Scanner Does NOT Do

To be explicit about scope:

- Does **not** execute any code from scanned repositories
- Does **not** make network requests (the scanner itself is offline-capable)
- Does **not** store scan results on any server (web UI uses client-side sessionStorage)
- Does **not** share results with third parties
- Does **not** require any external npm packages
- Does **not** read environment variables
- Does **not** write to the filesystem (except `--output` report file)
