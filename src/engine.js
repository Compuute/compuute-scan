// ─────────────────────────────────────────────
// Main Scan Engine
// ─────────────────────────────────────────────

function makeFinding(rule, file, line, code, guard) {
  return {
    id: rule.id,
    title: rule.title,
    layer: rule.layer,
    severity: guard?.mitigated ? downgradeSeverity(rule.severity) : rule.severity,
    owasp: rule.owasp,
    nis2: rule.nis2,
    gdpr: rule.gdpr || null,
    dora: rule.dora || null,
    file,
    line,
    code,
    mitigated: guard?.mitigated || false,
    guardLine: guard?.guardLine || null,
    guardCode: guard?.guardCode || null,
    description: rule.description,
    recommendation: rule.recommendation,
  };
}

function scanFile(filePath, repoPath, allRules, guardWindow) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const lines = content.split('\n');
  const relPath = path.relative(repoPath, filePath);
  const findings = [];

  for (const rule of allRules) {
    // Count-based detection: fires when pattern exceeds N occurrences in a file
    if (rule.countThreshold) {
      let count = 0;
      for (let i = 0; i < lines.length; i++) {
        if (rule.test && rule.test(lines[i])) count++;
      }
      if (count > rule.countThreshold) {
        findings.push(makeFinding(rule, relPath, null, `${count} occurrences found`));
      }
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      let matched = false;

      if (rule.test) {
        matched = rule.test(lines[i]);
      } else if (rule.multiLineTest) {
        matched = rule.multiLineTest(lines, i);
      }

      if (!matched) continue;
      if (rule.contextCheck && !rule.contextCheck(lines, i)) continue;

      // Check for inline ignore comment on the line above
      if (i > 0) {
        const ignoreMatch = IGNORE_PATTERN.exec(lines[i - 1]);
        if (ignoreMatch) {
          const ignoreRuleId = ignoreMatch[1];
          if (!ignoreRuleId || ignoreRuleId === rule.id) continue;
        }
      }

      const guard = (rule.guards && rule.guards.length > 0)
        ? checkGuard(lines, i, rule.guards, guardWindow)
        : null;

      findings.push(makeFinding(rule, relPath, i + 1, lines[i].trim().substring(0, MAX_CODE_SNIPPET), guard));
    }
  }

  return findings;
}

function runNegativeChecks(allContent, negativeRules, sourceFiles) {
  const findings = [];
  const hasRust = sourceFiles ? sourceFiles.some(f => f.endsWith('.rs')) : false;
  for (const rule of negativeRules) {
    // Skip context-specific rules when context doesn't apply
    if (rule.contextRequired === 'rust' && !hasRust) continue;
    if (!rule.pattern.test(allContent)) {
      findings.push(makeFinding(rule, '(entire codebase)', null, 'Pattern not found in any source file'));
    }
  }
  return findings;
}



