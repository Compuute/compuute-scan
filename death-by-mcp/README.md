# Death by MCP

How secure is your MCP server? Find out in 30 seconds.

Paste a GitHub repo URL. Get a security score. Share your results.

Supports TypeScript, JavaScript, Python, and Go -- covering 81% of the MCP ecosystem.

Powered by [compuute-scan](https://github.com/Compuute/compuute-scan) v0.3.0 (22 open-source rules, L0-L1).

For full L2-L4 security assessment: [compuute.se/audit](https://compuute.se/audit)

## Setup

Docker is **required** -- all scans run inside isolated containers. No untrusted code touches the host.

```bash
npm install
docker compose -f docker-compose.scanner.yml build
npm run dev
```

Every scan runs as a two-stage pipeline:

```
┌─────────────────┐         ┌──────────────────────────┐
│  Stage 1: Clone │         │  Stage 2: Scan           │
│  bridge network │────────▶│  network: none           │
│  hooks disabled │  volume │  read-only filesystem    │
│  non-root user  │         │  all caps dropped        │
│  256MB / 0.5CPU │         │  512MB / 1CPU            │
└─────────────────┘         └──────────────────────────┘
```

| Property | Clone container | Scan container |
|----------|----------------|----------------|
| Network | Bridge (git only) | **none** -- zero network stack |
| Git hooks | **Disabled** (core.hooksPath=/dev/null) | N/A |
| Filesystem | Read-only + tmpfs | **Read-only** |
| Capabilities | NET_RAW only | **All dropped** |
| User | Non-root (scanner) | Non-root (scanner) |

## Deploy

```bash
# Self-hosted (Docker required)
docker compose -f docker-compose.scanner.yml build
npm run build
npm start
```

## Tech Stack

- Next.js 15 (App Router)
- TypeScript
- Tailwind CSS
- Docker (production scanning isolation)
- Stateless (no database)

## Security & Ethics

- **Consent required**: Users must confirm ownership/permission before scanning
- **No public exposure**: Results shown only to the scanning user, never indexed or stored
- **Credential redaction**: Secrets, API keys, emails, connection strings are auto-redacted
- **No code retention**: Cloned repos are deleted immediately after scanning
- **Aggregated research only**: Any published ecosystem stats are anonymized -- no repos named without consent

See the [responsible disclosure policy](/about#responsible-disclosure) for details.

## Go-to-Market Strategy

See [GTM-PLAYBOOK.md](GTM-PLAYBOOK.md) for the legal-safe viral launch strategy.

## License

MIT
