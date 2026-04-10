// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

function main() {
  const opts = parseArgs(process.argv);

  if (opts.help || !opts.repoPath) {
    printUsage();
    process.exit(opts.help ? 0 : 1);
  }

  const repoPath = path.resolve(opts.repoPath);
  if (!fs.existsSync(repoPath)) {
    console.error(`Error: Path does not exist: ${repoPath}`);
    process.exit(2);
  }

  const startTime = Date.now();

  // Load config
  const config = loadConfig(repoPath);
  if (config && opts.verbose) {
    console.error('Loaded .compuute-scan.json');
  }

  // Walk files (respecting config ignore patterns)
  const allSourceFiles = walkDir(repoPath);
  const sourceFiles = config
    ? allSourceFiles.filter(f => !shouldIgnoreFile(path.relative(repoPath, f), config))
    : allSourceFiles;

  if (opts.verbose) {
    console.error(`Scanning ${sourceFiles.length} files in ${repoPath}...`);
    if (allSourceFiles.length !== sourceFiles.length) {
      console.error(`  (${allSourceFiles.length - sourceFiles.length} files excluded by config)`);
    }
  }

  // Build combined content for negative checks
  const contentParts = [];
  for (const f of sourceFiles) {
    const content = readFileSafe(f);
    if (content) {
      contentParts.push(content);
      if (opts.verbose) {
        console.error(`  ${path.relative(repoPath, f)}`);
      }
    }
  }
  const allContent = contentParts.join('\n');

  // Collect all per-file rules (apply config overrides)
  let allFileRules = [...L1_RULES, ...L2_RULES, ...L3_RULES, ...L4_RULES, ...L4_RULES_EXTRA];
  allFileRules = applyRuleConfig(allFileRules, config);

  // Run per-file scans
  let findings = [];
  for (const f of sourceFiles) {
    const guardWindow = config && config.guardWindow ? config.guardWindow : null;
    const fileFindings = scanFile(f, repoPath, allFileRules, guardWindow);
    findings.push(...fileFindings);
  }

  // Run negative checks (apply config overrides)
  let negativeRules = [...L1_NEGATIVE_RULES, ...L2_NEGATIVE_RULES, ...L3_NEGATIVE_RULES, ...L4_NEGATIVE_RULES];
  negativeRules = applyRuleConfig(negativeRules, config);
  findings.push(...runNegativeChecks(allContent, negativeRules, sourceFiles));

  // L0 Discovery
  const discovery = runL0Discovery(repoPath, allContent, sourceFiles);

  const durationMs = Date.now() - startTime;

  // Apply filters
  if (opts.layer) {
    findings = findings.filter(f => f.layer === opts.layer);
  }
  if (opts.minSeverity) {
    const minOrder = SEVERITY_ORDER[opts.minSeverity];
    if (minOrder !== undefined) {
      findings = findings.filter(f => SEVERITY_ORDER[f.severity] <= minOrder);
    }
  }

  // Sort by severity (critical first)
  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] || 99) - (SEVERITY_ORDER[b.severity] || 99));

  // Generate report
  let report;
  if (opts.sarif) {
    report = generateSarifReport(repoPath, findings, discovery, durationMs);
  } else if (opts.json) {
    report = generateJsonReport(repoPath, findings, discovery, durationMs);
  } else {
    report = generateMarkdownReport(repoPath, findings, discovery, durationMs);
  }

  // Output
  if (opts.output) {
    fs.writeFileSync(opts.output, report);
    console.error(`Report written to ${opts.output}`);
  } else {
    console.log(report);
  }

  // Upgrade notice (stderr so it doesn't pollute report output)
  if (!opts.json && !opts.sarif) {
    console.error('');
    console.error('L0-L1 scan complete. For knowledge graph-driven L2-L4 analysis + compliance mapping:');
    console.error('  https://compuute.se/audit');
  }

  // Determine exit code
  if (opts.failOnSeverity) {
    const threshold = SEVERITY_ORDER[opts.failOnSeverity];
    if (threshold !== undefined) {
      const hasFindings = findings.some(f => SEVERITY_ORDER[f.severity] <= threshold);
      if (hasFindings) {
        console.error(`\nFindings at or above "${opts.failOnSeverity}" severity detected — exiting with code 1.`);
        process.exit(1);
      }
    }
  }

  process.exit(0);
}

main();
