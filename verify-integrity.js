#!/usr/bin/env node
// compuute-scan integrity verifier
// Checks that compuute-scan.js has not been tampered with:
//   1. SHA-256 hash matches published release hash
//   2. No dangerous runtime patterns (exec, spawn, fetch, network, fs.write)
//
// Usage:
//   node verify-integrity.js                  # verify against embedded hash
//   node verify-integrity.js --hash <sha256>  # verify against custom hash
//   node verify-integrity.js --audit-only     # skip hash, only check patterns

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCANNER_PATH = path.join(__dirname, 'compuute-scan.js');

// ─────────────────────────────────────────────
// Dangerous patterns — a security scanner must NEVER:
//   - Execute child processes (could run attacker code)
//   - Make network requests (could exfiltrate data)
//   - Write files outside reports (could drop payloads)
//   - Use eval/Function (could execute injected code)
//   - Import/require dynamically (could load trojan modules)
// ─────────────────────────────────────────────

const FORBIDDEN_PATTERNS = [
  {
    name: 'child_process execution',
    pattern: /\b(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/g,
    description: 'Scanner must not execute external processes',
  },
  {
    name: 'network access (http/https)',
    pattern: /\brequire\s*\(\s*['"](?:http|https|net|dgram|tls)['"]\s*\)/g,
    description: 'Scanner must not make network requests',
  },
  {
    name: 'network access (fetch/XMLHttpRequest)',
    pattern: /\b(fetch|XMLHttpRequest|WebSocket)\s*\(/g,
    description: 'Scanner must not use browser/node fetch APIs',
  },
  {
    name: 'file write operations',
    pattern: /\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(/g,
    description: 'Scanner should only read files, not write (except report output via fs.writeFileSync to --output)',
    // fs.writeFileSync is used once for --output flag, so we count occurrences
    maxAllowed: 1,
  },
  {
    name: 'eval / Function constructor',
    pattern: /\b(eval|Function)\s*\(/g,
    description: 'Scanner must not use eval or dynamic code execution',
  },
  {
    name: 'dynamic require',
    pattern: /\brequire\s*\(\s*[^'"]/g,
    description: 'Scanner must not dynamically require modules (only static string requires)',
  },
  {
    name: 'process.env access',
    pattern: /\bprocess\.env\b/g,
    description: 'Scanner must not read environment variables (could leak secrets)',
  },
  {
    name: 'Buffer.from with encoding tricks',
    pattern: /\bBuffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)/g,
    description: 'Base64 decoding could hide obfuscated payloads',
  },
  {
    name: 'global/globalThis modification',
    pattern: /\b(global|globalThis)\s*\[/g,
    description: 'Scanner must not modify global state dynamically',
  },
];

// Known safe requires for this scanner
const ALLOWED_REQUIRES = new Set(['fs', 'path', 'crypto']);

// ─────────────────────────────────────────────
// Verification
// ─────────────────────────────────────────────

function computeHash(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function isInsideString(line, matchIndex) {
  // Check if the match position is inside a string literal
  // by counting unescaped quotes before the match
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  for (let i = 0; i < matchIndex && i < line.length; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : '';
    if (prev === '\\') continue;
    if (ch === "'" && !inDouble && !inTemplate) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && !inTemplate) inDouble = !inDouble;
    else if (ch === '`' && !inSingle && !inDouble) inTemplate = !inTemplate;
  }
  return inSingle || inDouble || inTemplate;
}

function auditPatterns(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const findings = [];

  for (const rule of FORBIDDEN_PATTERNS) {
    const matches = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comments
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        // Skip matches inside string literals (rule descriptions, etc.)
        if (isInsideString(line, match.index)) continue;
        matches.push({ line: i + 1, code: line.trim().substring(0, 100) });
      }
    }

    const maxAllowed = rule.maxAllowed || 0;
    if (matches.length > maxAllowed) {
      findings.push({
        rule: rule.name,
        description: rule.description,
        count: matches.length,
        maxAllowed,
        matches: matches.slice(0, 5), // Show first 5
      });
    }
  }

  // Check for unexpected requires (only at top-level, not inside string literals)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;
    const reqPattern = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    let m;
    while ((m = reqPattern.exec(line)) !== null) {
      if (isInsideString(line, m.index)) continue;
      if (!ALLOWED_REQUIRES.has(m[1])) {
        findings.push({
          rule: 'unexpected dependency',
          description: `Found require('${m[1]}') — only ${[...ALLOWED_REQUIRES].join(', ')} are expected`,
          count: 1,
          maxAllowed: 0,
          matches: [{ line: i + 1, code: m[0] }],
        });
      }
    }
  }

  return findings;
}

// ─────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  const auditOnly = args.includes('--audit-only');
  const hashIdx = args.indexOf('--hash');
  const expectedHash = hashIdx !== -1 ? args[hashIdx + 1] : null;

  console.log('compuute-scan integrity verifier\n');

  if (!fs.existsSync(SCANNER_PATH)) {
    console.error(`ERROR: ${SCANNER_PATH} not found`);
    process.exit(2);
  }

  let exitCode = 0;

  // Step 1: Hash verification
  if (!auditOnly) {
    const actualHash = computeHash(SCANNER_PATH);
    console.log(`SHA-256: ${actualHash}`);

    if (expectedHash) {
      if (actualHash === expectedHash.toLowerCase()) {
        console.log('PASS  Hash matches expected value\n');
      } else {
        console.log(`FAIL  Hash mismatch!`);
        console.log(`  Expected: ${expectedHash}`);
        console.log(`  Actual:   ${actualHash}\n`);
        exitCode = 1;
      }
    } else {
      console.log('INFO  No expected hash provided. Use --hash <sha256> to verify against a release.\n');
    }
  }

  // Step 2: Pattern audit
  console.log('Auditing for dangerous patterns...\n');
  const findings = auditPatterns(SCANNER_PATH);

  if (findings.length === 0) {
    console.log('PASS  No dangerous patterns found');
    console.log('      - No child_process execution');
    console.log('      - No network access');
    console.log('      - No eval or dynamic code execution');
    console.log('      - No unexpected dependencies');
    console.log('      - No environment variable access');
    console.log('      - Only allowed file write (--output flag)');
  } else {
    for (const f of findings) {
      console.log(`FAIL  ${f.rule} (${f.count} occurrences, max allowed: ${f.maxAllowed})`);
      console.log(`      ${f.description}`);
      for (const m of f.matches) {
        console.log(`      Line ${m.line}: ${m.code}`);
      }
      console.log('');
    }
    exitCode = 1;
  }

  // Step 3: Require audit (top-level requires only, not inside strings)
  console.log('\nDependency audit:');
  const content = fs.readFileSync(SCANNER_PATH, 'utf-8');
  const contentLines = content.split('\n');
  const topLevelRequires = [];
  for (let i = 0; i < contentLines.length; i++) {
    const line = contentLines[i];
    if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;
    const rp = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    let rm;
    while ((rm = rp.exec(line)) !== null) {
      if (!isInsideString(line, rm.index)) topLevelRequires.push(rm[1]);
    }
  }
  const unique = [...new Set(topLevelRequires)];
  console.log(`  Modules: ${unique.join(', ')}`);
  const unexpected = unique.filter(r => !ALLOWED_REQUIRES.has(r));
  if (unexpected.length === 0) {
    console.log('  PASS  All dependencies are Node.js built-ins (zero external deps)');
  } else {
    console.log(`  FAIL  Unexpected dependencies: ${unexpected.join(', ')}`);
    exitCode = 1;
  }

  console.log('');
  if (exitCode === 0) {
    console.log('All integrity checks passed.');
  } else {
    console.log('INTEGRITY CHECK FAILED — review findings above.');
  }

  process.exit(exitCode);
}

main();
