# Death by MCP

How secure is your MCP server? Find out in 30 seconds.

Paste a GitHub repo URL. Get a security score. Share your results.

Supports TypeScript, JavaScript, Python, and Go -- covering 81% of the MCP ecosystem.

Powered by [compuute-scan](https://github.com/Compuute/compuute-scan) v0.3.0 (22 open-source rules, L0-L1).

For full L2-L4 security assessment: [compuute.se/audit](https://compuute.se/audit)

## Setup

```bash
npm install
npm run dev
```

## Deploy

```bash
# Vercel (recommended)
npx vercel
```

## Tech Stack

- Next.js 15 (App Router)
- TypeScript
- Tailwind CSS
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
