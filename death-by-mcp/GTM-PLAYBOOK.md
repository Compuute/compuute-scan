# Death by MCP — Go-to-Market Playbook

> Legal-safe viral launch strategy for Death by MCP.
> Replaces the original "scan top 20 repos and tag maintainers" plan.

## Principles

1. **Never name specific repos/maintainers** in public without explicit consent
2. **Aggregated stats only** in all public content
3. **Responsible disclosure** — private notification, not public shaming
4. **Consent-first** — users scan their own repos, we don't scan for them

---

## Phase 1: Aggregated Research (Week 1-2)

### What to do

Scan the top 50 most-starred public MCP servers locally (using CLI, not the web tool).
Collect **aggregated, anonymized statistics only**.

### What to publish

Blog post / LinkedIn post:

> **"We scanned 50 of the most popular MCP servers. Here's what we found."**
>
> - X% had at least one critical finding (eval, pickle, command injection)
> - X% had CORS misconfiguration allowing any origin
> - X% had no security headers
> - X% had SSL/TLS verification disabled
> - X% had path traversal risks without sanitization
> - Average score: XX/100
>
> No servers are named. No maintainers are tagged.
> Run your own scan: [death-by-mcp.vercel.app]

### Why this works

- Same shock value as naming repos ("50% have critical vulns!")
- Zero legal risk — no defamation, no forced disclosure
- Drives traffic to the tool (people want to check their own server)
- Establishes Compuute as the authority on MCP security

---

## Phase 2: Private Outreach (Week 2-3)

### What to do

For the repos with critical findings, send **private** emails/DMs to maintainers:

> Subject: Security findings in [repo-name] MCP server
>
> Hi [name],
>
> We're Compuute AB, an MCP security company. During ecosystem research we
> found [N] security findings in [repo-name], including [severity] issues
> in [general category, e.g. "code execution" or "path traversal"].
>
> We'd like to share the full report privately. No public disclosure without
> your consent. Happy to help with remediation.
>
> Full report attached / available at [private link].
>
> Daniel @ Compuute AB
> daniel@compuute.se

### Rules

- **90-day disclosure window** (industry standard, matches Google Project Zero)
- **Never publish specific findings** without maintainer consent
- If maintainer doesn't respond after 90 days: still don't publish specifics,
  only include in aggregated anonymous stats
- Goal: build relationships, not burn bridges

### Conversion path

Maintainers who respond → offer free L0-L1 report → upsell to full L2-L4 audit.
Many popular MCP servers are built by companies, not individuals. Companies buy audits.

---

## Phase 3: Viral Loop (Week 3+)

### Self-serve scanning

The web UI is the primary growth engine:
1. Developer finds tool (via blog post, HN, Twitter)
2. Scans their own MCP server
3. Gets alarming score
4. Shares voluntarily ("Look what I got!")
5. Their followers scan their servers → loop

### Key design decisions for virality

- Score is 0-100 where 100 = worst → bigger number = more shareable
- Share card is visually striking (dark theme, red score)
- Share is opt-in, user's choice
- CTA on every result page → compuute.se/audit

### Content calendar

| Week | Content | Channel |
|------|---------|---------|
| 1 | "We scanned 50 MCP servers" blog post | LinkedIn, Twitter |
| 1 | Submit to Hacker News | HN |
| 2 | "5 most common MCP vulnerabilities" thread | Twitter, LinkedIn |
| 2 | Private outreach to top maintainers | Email |
| 3 | "How to secure your MCP server" guide | Blog, GitHub |
| 4 | "MCP Security Report Q2 2026" (aggregated) | Blog, PDF |

---

## Phase 4: Community Building (Month 2+)

- Open source the web UI (this repo)
- Accept PRs for new scan rules
- Monthly "State of MCP Security" report (always aggregated)
- Sponsor MCP-related meetups/events
- Guest posts on AI security blogs

---

## What NOT to Do

| Action | Risk | Alternative |
|--------|------|-------------|
| Tag maintainers on LinkedIn with findings | Defamation, public shaming | Private email with report |
| Publish leaderboard of vulnerable repos | Defamation, ToS violation | Aggregated anonymous stats |
| Show hardcoded secrets in web UI results | GDPR, trade secret exposure | Auto-redaction (implemented) |
| Scan private repos | Computer fraud (BrB 4:9c) | Public repos only, consent checkbox |
| Scan without user consent | Ethical violation | Consent checkbox required |
| Keep cloned code after scan | Data retention risk | Delete immediately (implemented) |

---

## Metrics to Track

| Metric | Target (Month 1) | Why |
|--------|------------------|-----|
| Unique scans | 500+ | Product-market fit signal |
| Return rate | >20% | Tool is useful, not just curiosity |
| Share rate | >5% of scans | Viral coefficient |
| Blog post views | 10,000+ | Content-market fit |
| Audit inquiries | 5+ | Revenue signal |
| GitHub stars (compuute-scan) | 200+ | Open source traction |

---

**Compuute AB** — Agentic AI Security
daniel@compuute.se | compuute.se
