# compuute-scan — agent working notes

Global verification rules in `~/.claude/CLAUDE.md` apply here. Repo-specific
additions below.

---

## Buyer context

This repo will be evaluated by security-conscious enterprise buyers (CISOs,
security engineers, pentest firms). Every artifact is read against that lens:

- **Git history must be clean.** Author + committer = `Compuute` everywhere.
  Verify after each commit: `git log -1 --format='%h | %an / %cn'`.
- **Released tags don't move.** Corrections ship as the next version.
- **Framing consistency in CHANGELOG/READMEs.** A rule framed as "pattern-
  breadth detector with required triage" cannot also be measured as having
  an "FP rate" — pattern matches under that lens are not FPs. Pick one.
- **No overclaim in finding output.** If a rule reads syntax, the finding
  description must say so explicitly. Severity must reflect what static
  analysis can belägga, never what it intuitively *seems* to imply.

## Working conventions

- **Build flow:** Edit `src/*.js` → `npm run build` → never edit `compuute-scan.js` directly.
- **Tests:** `npm test` runs `death-by-mcp/test.js`. New rules require positive + negative fixtures in `death-by-mcp/fixtures-<rule-id>/` and assertions in test.js.
- **Self-scan version pin:** When bumping `src/constants.js` VERSION, also bump `package.json`, `scripts/build.js` HEADER, and the `selfScanJson.version === '0.x.y'` assertion in test.js.
- **prepublishOnly hook:** `npm run verify --audit-only && npm test` must both pass before publish.
- **Batch validation:** `node scripts/scan-nightly-batch.js && node scripts/aggregate-nightly.js` against `.nightly-work/` (gitignored).
- **Manual triage required for new rules:** Read each hit in batch output against the threat model. Record verdict per row. "67% match rate" is not a verdict; "1 runtime exposure / 2 build-time pattern matches" is.

## Local-only artifacts (gitignored)

- `.nightly-work/` — cloned production MCP servers for batch validation
- `.secrets` — local API keys (never commit)
- `.claude/` — local agent config
- `reports/nightly-batch-*/` — generated batch scan output

## Rule numbering

L1-001 through L1-038 are in use as of v0.6.1. L1-011 and L1-027 are NEGATIVE
rules (whole-codebase checks). Before adding a new rule: `grep -n "id: 'L1-"
src/rules-l1.js` to find next free integer.
