// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────

function loadConfig(repoPath) {
  const configPath = path.join(repoPath, '.compuute-scan.json');
  if (!fs.existsSync(configPath)) return null;
  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    console.error(`[warn] Failed to parse .compuute-scan.json: ${err.message}`);
    return null;
  }
}

function shouldIgnoreFile(relPath, config) {
  if (!config || !config.ignore || !Array.isArray(config.ignore)) return false;
  for (const pattern of config.ignore) {
    // Simple glob: "test/**" matches "test/foo.js", "*.test.js" matches "bar.test.js"
    const re = new RegExp(
      '^' + pattern
        .replace(/\./g, '\\.')
        .replace(/\*\*/g, '(.+)')
        .replace(/\*/g, '([^/]+)')
      + '$'
    );
    if (re.test(relPath)) return true;
  }
  return false;
}

function applyRuleConfig(rules, config) {
  if (!config || !config.rules) return rules;
  return rules.filter(rule => {
    const override = config.rules[rule.id];
    if (!override) return true;
    if (override.enabled === false) return false;
    if (override.severity && SEVERITY_ORDER[override.severity] !== undefined) {
      rule.severity = override.severity;
    }
    return true;
  });
}
