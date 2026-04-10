#!/usr/bin/env node
// Death by MCP — Unit tests
// Runs without Docker. Tests all logic except actual container execution.

'use strict';

let pass = 0;
let fail = 0;

function assert(name, condition) {
  if (condition) {
    console.log(`  PASS  ${name}`);
    pass++;
  } else {
    console.log(`  FAIL  ${name}`);
    fail++;
  }
}

// ─────────────────────────────────────────────
// URL Validation
// ─────────────────────────────────────────────

console.log('\n=== URL Validation ===');

const GITHUB_URL_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/;

function validateRepoUrl(url) {
  const trimmed = url.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  if (!GITHUB_URL_RE.test(trimmed) && !GITHUB_URL_RE.test(trimmed + '.git')) {
    return null;
  }
  return trimmed;
}

// Valid URLs
assert('Valid: standard GitHub URL',
  validateRepoUrl('https://github.com/Compuute/compuute-scan') !== null);
assert('Valid: with .git suffix',
  validateRepoUrl('https://github.com/org/repo.git') !== null);
assert('Valid: with trailing slash',
  validateRepoUrl('https://github.com/org/repo/') !== null);
assert('Valid: hyphenated names',
  validateRepoUrl('https://github.com/my-org/my-repo') !== null);
assert('Valid: dotted names',
  validateRepoUrl('https://github.com/org/repo.js') !== null);

// Invalid URLs — must reject
assert('Reject: GitLab',
  validateRepoUrl('https://gitlab.com/org/repo') === null);
assert('Reject: no repo path',
  validateRepoUrl('https://github.com/org') === null);
assert('Reject: FTP',
  validateRepoUrl('ftp://github.com/org/repo') === null);
assert('Reject: command injection semicolon',
  validateRepoUrl('https://github.com/org/repo; rm -rf /') === null);
assert('Reject: command injection $(...)',
  validateRepoUrl('https://github.com/org/repo$(whoami)') === null);
assert('Reject: command injection backtick',
  validateRepoUrl('https://github.com/org/repo`id`') === null);
assert('Reject: path traversal',
  validateRepoUrl('https://github.com/org/../../../etc/passwd') === null);
assert('Reject: spaces',
  validateRepoUrl('https://github.com/org/repo name') === null);
assert('Reject: empty',
  validateRepoUrl('') === null);
assert('Reject: HTTP (not HTTPS)',
  validateRepoUrl('http://github.com/org/repo') === null);

// ─────────────────────────────────────────────
// Scoring
// ─────────────────────────────────────────────

console.log('\n=== Scoring ===');

function calculateScore(findings) {
  let critical = 0, high = 0, medium = 0, low = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': critical++; break;
      case 'high': high++; break;
      case 'medium': medium++; break;
      case 'low': low++; break;
    }
  }
  return Math.min(100, (critical * 25) + (high * 15) + (medium * 8) + (low * 3));
}

function getRiskLevel(score) {
  if (score === 0) return 'clean';
  if (score <= 15) return 'low';
  if (score <= 40) return 'medium';
  if (score <= 70) return 'high';
  return 'critical';
}

assert('Score: 0 findings = 0',
  calculateScore([]) === 0);
assert('Score: 1 critical = 25',
  calculateScore([{ severity: 'critical' }]) === 25);
assert('Score: 1 high = 15',
  calculateScore([{ severity: 'high' }]) === 15);
assert('Score: 1 medium = 8',
  calculateScore([{ severity: 'medium' }]) === 8);
assert('Score: 1 low = 3',
  calculateScore([{ severity: 'low' }]) === 3);
assert('Score: mixed = 25+15+8+3 = 51',
  calculateScore([
    { severity: 'critical' },
    { severity: 'high' },
    { severity: 'medium' },
    { severity: 'low' },
  ]) === 51);
assert('Score: capped at 100',
  calculateScore(Array(10).fill({ severity: 'critical' })) === 100);
assert('Score: 4 critical + 1 high = 100 (capped)',
  calculateScore([
    ...Array(4).fill({ severity: 'critical' }),
    { severity: 'high' },
  ]) === 100);

assert('Risk: 0 = clean',
  getRiskLevel(0) === 'clean');
assert('Risk: 3 = low',
  getRiskLevel(3) === 'low');
assert('Risk: 15 = low',
  getRiskLevel(15) === 'low');
assert('Risk: 16 = medium',
  getRiskLevel(16) === 'medium');
assert('Risk: 40 = medium',
  getRiskLevel(40) === 'medium');
assert('Risk: 41 = high',
  getRiskLevel(41) === 'high');
assert('Risk: 70 = high',
  getRiskLevel(70) === 'high');
assert('Risk: 71 = critical',
  getRiskLevel(71) === 'critical');
assert('Risk: 100 = critical',
  getRiskLevel(100) === 'critical');

// ─────────────────────────────────────────────
// Redaction
// ─────────────────────────────────────────────

console.log('\n=== Credential Redaction ===');

const SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|password|token|credential|auth)[\s]*[=:]\s*['"][^'"]{4,}['"]/gi,
  /['"][A-Za-z0-9+/=]{20,}['"]/g,
  /(?:sk|pk|key|token|secret)[_-]?[a-z]*[_-][a-zA-Z0-9]{10,}/gi,
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
  /(?:\d{1,3}\.){3}\d{1,3}/g,
];

function redactString(text) {
  let result = text;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

assert('Redact: API key assignment',
  !redactString('api_key = "sk-abc123456789"').includes('sk-abc123456789'));
assert('Redact: password assignment',
  !redactString('password = "superSecret123"').includes('superSecret123'));
assert('Redact: token assignment',
  !redactString('token = "mySecretTokenValue"').includes('mySecretTokenValue'));
assert('Redact: MongoDB connection string',
  !redactString('mongodb://admin:pass@db.example.com/prod').includes('admin:pass'));
assert('Redact: PostgreSQL connection string',
  !redactString('postgres://user:pw@host/db').includes('user:pw'));
assert('Redact: email address',
  !redactString('Found user daniel@compuute.se in code').includes('daniel@compuute.se'));
assert('Redact: IP address',
  !redactString('Binding to 192.168.1.100').includes('192.168.1.100'));
assert('Redact: Stripe secret key',
  !redactString('sk_live_abcdef1234567890').includes('sk_live_abcdef1234567890'));
assert('Redact: Stripe public key',
  !redactString('pk_test_abcdef1234567890').includes('pk_test_abcdef1234567890'));
assert('Keep: normal code (no false positive)',
  redactString('eval(req.body.code) is dangerous') === 'eval(req.body.code) is dangerous');
assert('Keep: short strings (no over-redaction)',
  redactString('Use crypto.randomUUID() instead') === 'Use crypto.randomUUID() instead');

// ─────────────────────────────────────────────
// File Path Stripping
// ─────────────────────────────────────────────

console.log('\n=== File Path Stripping ===');

function stripPath(filePath) {
  return filePath.split('/').slice(-2).join('/');
}

assert('Strip: full absolute path',
  stripPath('/tmp/mcp-scan-abc123/repo/src/server.ts') === 'src/server.ts');
assert('Strip: deep path',
  stripPath('/work/myrepo/lib/handlers/auth.py') === 'handlers/auth.py');
assert('Strip: short path unchanged',
  stripPath('src/index.js') === 'src/index.js');

// ─────────────────────────────────────────────
// Rate Limiter
// ─────────────────────────────────────────────

console.log('\n=== Rate Limiter ===');

const hits = new Map();
const WINDOW_MS = 60 * 60 * 1000;
const MAX_REQUESTS = 10;

function checkRateLimit(ip) {
  const now = Date.now();
  const timestamps = hits.get(ip) || [];
  const valid = timestamps.filter((t) => now - t < WINDOW_MS);
  if (valid.length >= MAX_REQUESTS) {
    hits.set(ip, valid);
    return { allowed: false, remaining: 0 };
  }
  valid.push(now);
  hits.set(ip, valid);
  return { allowed: true, remaining: MAX_REQUESTS - valid.length };
}

// First 10 requests should pass
for (let i = 0; i < 10; i++) {
  const result = checkRateLimit('test-ip');
  assert(`Rate limit: request ${i + 1} allowed (remaining: ${result.remaining})`,
    result.allowed === true);
}

// 11th request should be blocked
const blocked = checkRateLimit('test-ip');
assert('Rate limit: request 11 blocked',
  blocked.allowed === false && blocked.remaining === 0);

// Different IP should still work
const otherIp = checkRateLimit('other-ip');
assert('Rate limit: different IP allowed',
  otherIp.allowed === true);

// ─────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────

console.log('\n' + '='.repeat(44));
console.log(` Results: ${pass} passed, ${fail} failed / ${pass + fail} total`);
console.log('='.repeat(44));

if (fail > 0) {
  process.exit(1);
} else {
  console.log('\nAll tests passed!\n');
}
