// ─────────────────────────────────────────────
// Report: Markdown
// ─────────────────────────────────────────────

function summarizeFindings(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const layers = {};
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
    layers[f.layer] = (layers[f.layer] || 0) + 1;
  }
  return { summary, layers };
}

function generateMarkdownReport(repoPath, findings, discovery, durationMs) {
  const repoName = path.basename(path.resolve(repoPath));
  const date = new Date().toISOString().split('T')[0];
  const filesScanned = discovery.totalSourceFiles;
  const { summary, layers } = summarizeFindings(findings);

  function layerEmoji(count) {
    if (count === 0 || count === undefined) return '\u2705';
    if (count <= 2) return '\u26A0\uFE0F';
    return '\uD83D\uDD34';
  }

  const layerDescriptions = {
    L0: 'Discovery & Metadata',
    L1: 'Sandboxing & Code Execution',
    L2: 'Authorization & Secrets',
    L3: 'Tool Integrity & Data Handling',
    L4: 'Monitoring & Logging',
  };

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const severityLabels = {
    critical: '\uD83D\uDD34 CRITICAL',
    high: '\uD83D\uDFE0 HIGH',
    medium: '\uD83D\uDFE1 MEDIUM',
    low: '\uD83D\uDFE2 LOW',
    info: '\u2139\uFE0F INFO',
  };

  const p = [];

  // Header
  p.push(`# MCP Security Scan Report\n`);
  p.push(`| Field | Value |\n|-------|-------|`);
  p.push(`| **Repository** | \`${repoName}\` |`);
  p.push(`| **Date** | ${date} |`);
  p.push(`| **Files Scanned** | ${filesScanned} |`);
  p.push(`| **Scan Duration** | ${(durationMs / 1000).toFixed(2)}s |`);
  p.push(`| **Scanner** | compuute-scan v${VERSION} |\n`);

  // Executive Summary
  p.push(`## Executive Summary\n`);
  p.push(`| Severity | Count |\n|----------|-------|`);
  p.push(`| \uD83D\uDD34 Critical | ${summary.critical} |`);
  p.push(`| \uD83D\uDFE0 High | ${summary.high} |`);
  p.push(`| \uD83D\uDFE1 Medium | ${summary.medium} |`);
  p.push(`| \uD83D\uDFE2 Low | ${summary.low} |`);
  p.push(`| Total | ${findings.length} |\n`);

  // Layer Assessment
  p.push(`## Layer Assessment\n`);
  p.push(`| Layer | Status | Findings | Description |\n|-------|--------|----------|-------------|`);
  for (const l of ['L0', 'L1']) {
    const count = layers[l] || 0;
    p.push(`| ${l} | ${layerEmoji(count)} | ${count} | ${layerDescriptions[l]} |`);
  }
  p.push(`| L2-L4 | — | — | [Available in Compuute Professional Audit](https://compuute.se/audit) |\n`);

  // Detailed Findings (grouped by severity)
  p.push(`## Detailed Findings\n`);

  for (const sev of severityOrder) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    p.push(`### ${severityLabels[sev]}\n`);

    for (const f of sevFindings) {
      p.push(`#### ${f.id}: ${f.title}\n`);
      p.push(`| Field | Value |\n|-------|-------|`);
      p.push(`| **Severity** | ${sev.toUpperCase()}${f.mitigated ? ' (Mitigated)' : ''} |`);
      p.push(`| **Layer** | ${f.layer} |`);
      p.push(`| **OWASP** | ${f.owasp} |`);
      p.push(`| **NIS2** | ${f.nis2} |`);
      if (f.gdpr) p.push(`| **GDPR** | ${f.gdpr} |`);
      if (f.dora) p.push(`| **DORA** | ${f.dora} |`);
      if (f.file) p.push(`| **File** | \`${f.file}\` |`);
      if (f.line) p.push(`| **Line** | ${f.line} |`);
      p.push('');

      if (f.code) {
        p.push(`**Code:**\n\`\`\`\n${f.code}\n\`\`\`\n`);
      }

      if (f.mitigated) {
        p.push(`> \u2705 **Mitigated** — Guard detected at line ${f.guardLine}: \`${f.guardCode}\`\n`);
      }

      p.push(`**Description:** ${f.description}\n`);
      p.push(`**Recommendation:** ${f.recommendation}\n`);
      p.push(`---\n`);
    }
  }

  // L0 Discovery
  p.push(`## L0: Discovery\n`);
  p.push(`| Property | Value |\n|----------|-------|`);
  p.push(`| **Transport** | ${discovery.transports.length ? discovery.transports.join(', ') : 'Not detected'} |`);
  p.push(`| **MCP Tools** | ~${discovery.toolCount} detected |`);
  p.push(`| **Dependency Pinning** | ${discovery.hasDependencyPinning ? '\u2705 Yes' : '\u274C No'} |`);
  p.push(`| **Containerization** | ${discovery.hasContainerization ? '\u2705 Yes' : '\u274C No'} |`);
  if (discovery.dependencies.length > 0) {
    p.push(`| **Dependencies** | ${discovery.dependencies.length} (${discovery.dependencyFile}) |`);
  }
  p.push('');

  if (discovery.dependencies.length > 0) {
    p.push(`<details>\n<summary>Dependency List</summary>\n`);
    for (const dep of discovery.dependencies) {
      p.push(`- ${dep}`);
    }
    p.push(`\n</details>\n`);
  }

  // Footer
  p.push(`---\n`);
  p.push(`## Full Security Assessment\n`);
  p.push(`This scan covers **L0 Discovery + L1 Sandboxing** (${findings.length} findings).\n`);
  p.push(`Production MCP deployments need **knowledge graph-driven analysis** (L2-L4):\n`);
  p.push(`- **L2 Authorization** — RBAC, secret management, JWT/OAuth, PII/GDPR compliance`);
  p.push(`- **L3 Tool Integrity** — SSRF, injection, prompt poisoning, supply chain`);
  p.push(`- **L4 Runtime Monitoring** — audit logging, rate limiting, error leakage\n`);
  p.push(`**49 rules. Full taint tracking. Attack path visualization. OWASP (10/10). NIS2 (7/7). GDPR (6/6). DORA.**\n`);
  p.push(`> [Book a Compuute Security Assessment](https://compuute.se/audit) — knowledge graph analysis, not just pattern matching\n`);
  p.push(`*Generated by compuute-scan v${VERSION} (open source) | Compuute AB*`);

  return p.join('\n');
}

// ─────────────────────────────────────────────
// Report: JSON
// ─────────────────────────────────────────────

function generateJsonReport(repoPath, findings, discovery, durationMs) {
  const repoName = path.basename(path.resolve(repoPath));
  const { summary, layers } = summarizeFindings(findings);

  return JSON.stringify({
    scanner: 'compuute-scan',
    version: VERSION,
    tier: 'open-source',
    layersCovered: ['L0', 'L1'],
    repo: repoName,
    date: new Date().toISOString(),
    filesScanned: discovery.totalSourceFiles,
    scanDurationMs: durationMs,
    summary,
    layers,
    l0Discovery: discovery,
    findings,
    upgrade: {
      message: 'This scan covers L0-L1 (pattern matching). Full L2-L4 assessment uses knowledge graph-driven analysis with taint tracking and attack path visualization.',
      url: 'https://compuute.se/audit',
    },
  }, null, 2);
}

function generateSarifReport(repoPath, findings, discovery, durationMs) {
  const repoName = path.basename(path.resolve(repoPath));

  const severityToSarif = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
  };

  const rules = [];
  const ruleIndex = {};
  const results = [];

  for (const f of findings) {
    if (!(f.id in ruleIndex)) {
      ruleIndex[f.id] = rules.length;
      rules.push({
        id: f.id,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        helpUri: 'https://compuute.se',
        properties: {
          layer: f.layer,
          owasp: f.owasp || '',
          nis2: f.nis2 || '',
          gdpr: f.gdpr || '',
          dora: f.dora || '',
        },
      });
    }

    if (f.file) {
      results.push({
        ruleId: f.id,
        ruleIndex: ruleIndex[f.id],
        level: severityToSarif[f.severity] || 'warning',
        message: { text: f.recommendation || f.description || f.title },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
            region: { startLine: f.line || 1 },
          },
        }],
        properties: {
          severity: f.severity,
          mitigated: f.mitigated || false,
        },
      });
    }
  }

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'compuute-scan',
          version: VERSION,
          informationUri: 'https://github.com/Compuute/compuute-scan',
          rules,
        },
      },
      results,
      invocations: [{
        executionSuccessful: true,
        properties: {
          filesScanned: discovery.totalSourceFiles,
          durationMs,
        },
      }],
    }],
  }, null, 2);
}


