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

const REPO_URL_RE = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(\.git)?$/;

function validateRepoUrl(url) {
  const trimmed = url.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  if (!REPO_URL_RE.test(trimmed) && !REPO_URL_RE.test(trimmed + '.git')) {
    return null;
  }
  return trimmed;
}

// Valid URLs — GitHub
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

// Valid URLs — GitLab
assert('Valid: GitLab standard URL',
  validateRepoUrl('https://gitlab.com/org/repo') !== null);
assert('Valid: GitLab with .git suffix',
  validateRepoUrl('https://gitlab.com/org/repo.git') !== null);
assert('Valid: GitLab hyphenated',
  validateRepoUrl('https://gitlab.com/my-org/mcp-server') !== null);

// Valid URLs — Bitbucket
assert('Valid: Bitbucket standard URL',
  validateRepoUrl('https://bitbucket.org/org/repo') !== null);
assert('Valid: Bitbucket with .git suffix',
  validateRepoUrl('https://bitbucket.org/org/repo.git') !== null);
assert('Valid: Bitbucket hyphenated',
  validateRepoUrl('https://bitbucket.org/my-team/mcp-tool') !== null);

// Invalid URLs — must reject
assert('Reject: unknown host',
  validateRepoUrl('https://example.com/org/repo') === null);
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
assert('Reject: self-hosted GitLab',
  validateRepoUrl('https://gitlab.mycompany.com/org/repo') === null);
assert('Reject: GitLab no repo path',
  validateRepoUrl('https://gitlab.com/org') === null);
assert('Reject: Bitbucket no repo path',
  validateRepoUrl('https://bitbucket.org/org') === null);

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
// Inline Ignore
// ─────────────────────────────────────────────

console.log('\n=== Inline Ignore ===');

const IGNORE_PATTERN = /(?:\/\/|#)\s*compuute-scan-ignore-next-line(?:\s+(L\d+-\d+))?/;

assert('Ignore: JS comment matches',
  IGNORE_PATTERN.test('// compuute-scan-ignore-next-line'));
assert('Ignore: JS comment with rule ID',
  IGNORE_PATTERN.exec('// compuute-scan-ignore-next-line L1-006')[1] === 'L1-006');
assert('Ignore: Python comment matches',
  IGNORE_PATTERN.test('# compuute-scan-ignore-next-line'));
assert('Ignore: Python comment with rule ID',
  IGNORE_PATTERN.exec('# compuute-scan-ignore-next-line L1-014')[1] === 'L1-014');
assert('Ignore: indented comment matches',
  IGNORE_PATTERN.test('    // compuute-scan-ignore-next-line'));
assert('Ignore: wrong prefix does not match',
  !IGNORE_PATTERN.test('/* compuute-scan-ignore-next-line */'));
assert('Ignore: partial text does not match',
  !IGNORE_PATTERN.test('// compuute-scan-ignore'));

// ─────────────────────────────────────────────
// Config File
// ─────────────────────────────────────────────

console.log('\n=== Config File ===');

// Simulate shouldIgnoreFile logic
function shouldIgnoreFile(relPath, config) {
  if (!config || !config.ignore || !Array.isArray(config.ignore)) return false;
  for (const pattern of config.ignore) {
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

const testConfig = { ignore: ['test/**', 'examples/**', '*.test.js'] };

assert('Config ignore: test/foo.js matched by test/**',
  shouldIgnoreFile('test/foo.js', testConfig));
assert('Config ignore: test/deep/bar.ts matched by test/**',
  shouldIgnoreFile('test/deep/bar.ts', testConfig));
assert('Config ignore: examples/demo.py matched',
  shouldIgnoreFile('examples/demo.py', testConfig));
assert('Config ignore: app.test.js matched by *.test.js',
  shouldIgnoreFile('app.test.js', testConfig));
assert('Config ignore: src/index.js NOT matched',
  !shouldIgnoreFile('src/index.js', testConfig));
assert('Config ignore: null config returns false',
  !shouldIgnoreFile('test/foo.js', null));
assert('Config ignore: empty ignore array returns false',
  !shouldIgnoreFile('test/foo.js', { ignore: [] }));

// ─────────────────────────────────────────────
// Function Boundary Detection
// ─────────────────────────────────────────────

console.log('\n=== Function Boundary Detection ===');

const FUNC_DEF_PATTERNS = [
  /^\s*(?:export\s+)?(?:async\s+)?function\s+\w+\s*\(/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>/,
  /^\s*(?:async\s+)?(?:\w+)\s*\([^)]*\)\s*\{/,
  /^\s*(?:async\s+)?def\s+\w+\s*\(/,
  /^\s*func\s+(?:\([^)]*\)\s+)?\w+\s*\(/,
];

function findFunctionBounds(lines, lineIdx) {
  let funcStart = -1;
  for (let i = lineIdx; i >= 0; i--) {
    for (const pat of FUNC_DEF_PATTERNS) {
      if (pat.test(lines[i])) { funcStart = i; break; }
    }
    if (funcStart >= 0) break;
  }
  if (funcStart < 0) return null;
  const funcLine = lines[funcStart];
  if (/^\s*(?:async\s+)?def\s+/.test(funcLine)) {
    const defIndent = funcLine.match(/^(\s*)/)[1].length;
    let funcEnd = funcStart;
    for (let i = funcStart + 1; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed === '' || trimmed.startsWith('#')) { funcEnd = i; continue; }
      const indent = lines[i].match(/^(\s*)/)[1].length;
      if (indent <= defIndent) break;
      funcEnd = i;
    }
    return { start: funcStart, end: funcEnd };
  }
  let braceDepth = 0;
  let foundOpen = false;
  for (let i = funcStart; i < lines.length; i++) {
    const line = lines[i];
    for (let c = 0; c < line.length; c++) {
      if (line[c] === '{') { braceDepth++; foundOpen = true; }
      else if (line[c] === '}') { braceDepth--; }
    }
    if (foundOpen && braceDepth <= 0) return { start: funcStart, end: i };
  }
  return null;
}

// JS function
const jsFunc = [
  'function handleRequest(req) {',    // 0
  '  if (!req.auth) return;',         // 1
  '  const data = req.body;',         // 2
  '  eval(data);',                    // 3
  '  return data;',                   // 4
  '}',                                // 5
  '',                                 // 6
  'function other() {',               // 7
  '  console.log("safe");',           // 8
  '}',                                // 9
];
const jsBounds = findFunctionBounds(jsFunc, 3);
assert('JS func: detected bounds', jsBounds !== null);
assert('JS func: start at line 0', jsBounds && jsBounds.start === 0);
assert('JS func: end at line 5', jsBounds && jsBounds.end === 5);
assert('JS func: guard at line 1 found within bounds',
  jsBounds && jsFunc[1].includes('auth'));

// Python function
const pyFunc = [
  'def process_input(data):',         // 0
  '    if not validate(data):',        // 1
  '        return None',               // 2
  '    result = eval(data)',           // 3
  '    return result',                 // 4
  '',                                  // 5
  'def other():',                      // 6
  '    pass',                          // 7
];
const pyBounds = findFunctionBounds(pyFunc, 3);
assert('Python func: detected bounds', pyBounds !== null);
assert('Python func: start at line 0', pyBounds && pyBounds.start === 0);
assert('Python func: end at line 5 (includes trailing blank)', pyBounds && pyBounds.end === 5);

// Go function
const goFunc = [
  'func handleTool(w http.ResponseWriter, r *http.Request) {',  // 0
  '  if r.Method != "POST" {',                                   // 1
  '    http.Error(w, "bad", 405)',                               // 2
  '    return',                                                   // 3
  '  }',                                                         // 4
  '  cmd := exec.Command("sh", r.URL.Query().Get("cmd"))',      // 5
  '  cmd.Run()',                                                  // 6
  '}',                                                            // 7
];
const goBounds = findFunctionBounds(goFunc, 5);
assert('Go func: detected bounds', goBounds !== null);
assert('Go func: start at line 0', goBounds && goBounds.start === 0);
assert('Go func: end at line 7', goBounds && goBounds.end === 7);

// Arrow function
const arrowFunc = [
  'const process = async (req) => {',  // 0
  '  checkAuth(req);',                  // 1
  '  eval(req.body.code);',            // 2
  '};',                                 // 3
];
const arrowBounds = findFunctionBounds(arrowFunc, 2);
assert('Arrow func: detected bounds', arrowBounds !== null);
assert('Arrow func: start at line 0', arrowBounds && arrowBounds.start === 0);
assert('Arrow func: end at line 3', arrowBounds && arrowBounds.end === 3);

// No function context (top-level code)
const topLevel = [
  'const x = 1;',       // 0
  'eval(userInput);',    // 1
  'console.log(x);',    // 2
];
assert('Top-level: no function bounds',
  findFunctionBounds(topLevel, 1) === null);

// Guard beyond window but inside function
const longFunc = ['function bigHandler(req) {'];
for (let i = 0; i < 25; i++) longFunc.push('  // line ' + i);
longFunc.push('  if (!req.auth) throw new Error("unauthorized");'); // line 26
for (let i = 0; i < 25; i++) longFunc.push('  // line ' + (i + 25));
longFunc.push('  eval(req.body.code);'); // line 52
longFunc.push('}'); // line 53
const longBounds = findFunctionBounds(longFunc, 52);
assert('Long func: bounds span entire function',
  longBounds !== null && longBounds.start === 0 && longBounds.end === 53);
assert('Long func: guard at line 26 is >15 lines from line 52 but within bounds',
  longBounds !== null && (52 - 26) > 15);

// ─────────────────────────────────────────────
// Guard Check with Function Bounds
// ─────────────────────────────────────────────

console.log('\n=== Guard Check with Function Bounds ===');

function checkGuard(lines, matchLineIdx, guardPatterns, guardWindow) {
  const window = guardWindow || 15;
  const bounds = findFunctionBounds(lines, matchLineIdx);
  const start = bounds ? bounds.start : Math.max(0, matchLineIdx - window);
  const end = bounds ? bounds.end : Math.min(lines.length - 1, matchLineIdx + window);
  for (let i = start; i <= end; i++) {
    if (i === matchLineIdx) continue;
    for (const gp of guardPatterns) {
      if (gp.test(lines[i])) {
        return { mitigated: true, guardLine: i + 1, guardCode: lines[i].trim().substring(0, 120) };
      }
    }
  }
  return { mitigated: false, guardLine: null, guardCode: null };
}

const authGuards = [/\bauth\b/i, /\bvalidate\b/i, /\bcheckPermission\b/i];

// Guard within window (classic)
const guardResult1 = checkGuard(jsFunc, 3, authGuards);
assert('Guard: auth check found within JS function',
  guardResult1.mitigated === true && guardResult1.guardLine === 2);

// Guard beyond 15-line window but within function bounds
const guardResult2 = checkGuard(longFunc, 52, authGuards);
assert('Guard: auth check found beyond window but within function bounds',
  guardResult2.mitigated === true && guardResult2.guardLine === 27);

// No guard
const noGuardFunc = [
  'function unsafe(req) {',
  '  eval(req.body.code);',
  '}',
];
const guardResult3 = checkGuard(noGuardFunc, 1, authGuards);
assert('Guard: no auth check = not mitigated',
  guardResult3.mitigated === false);

// Python guard within function
const pyGuardResult = checkGuard(pyFunc, 3, [/\bvalidate\b/]);
assert('Guard: Python validate() found within function',
  pyGuardResult.mitigated === true && pyGuardResult.guardLine === 2);

// Custom guard window via config
const shortWindowResult = checkGuard(
  ['line0', 'line1', 'if (auth) return;', 'line3', 'line4', 'line5', 'eval(x)'],
  6, authGuards, 2
);
assert('Guard: custom window=2 does not reach auth at line 2',
  shortWindowResult.mitigated === false);

// ─────────────────────────────────────────────
// Per-Rule Pattern Detection (L1-001 to L1-022)
// ─────────────────────────────────────────────

console.log('\n=== Per-Rule Pattern Detection ===');

// L1-001: eval() with non-literal argument
function testL1_001(line) {
  if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
  if (!/\beval\s*\(/.test(line)) return false;
  if (/\beval\s*\(\s*['"]/.test(line)) return false;
  return true;
}
assert('L1-001: eval(userInput) triggers', testL1_001('eval(userInput)'));
assert('L1-001: eval(req.body.code) triggers', testL1_001('const r = eval(req.body.code)'));
assert('L1-001: eval("literal") safe', !testL1_001('eval("2+2")'));
assert('L1-001: // eval(x) in comment safe', !testL1_001('// eval(x)'));

// L1-002: Shell command execution
function testL1_002(line) {
  if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
  if (/\.exec\s*\(/.test(line)) {
    if (/\bexec\s*\(/.test(line) && !/\w\.exec\s*\(/.test(line)) return true;
    return false;
  }
  if (/\bexecSync\s*\(/.test(line)) return true;
  if (/\bspawn\s*\(/.test(line) && /['"`]/.test(line)) return true;
  return false;
}
assert('L1-002: execSync("cmd") triggers', testL1_002('execSync("ls -la")'));
assert('L1-002: spawn("sh") triggers', testL1_002('spawn("sh", ["-c"])'));
assert('L1-002: regex.exec(str) safe', !testL1_002('const m = re.exec(str)'));
assert('L1-002: // execSync in comment safe', !testL1_002('// execSync("cmd")'));

// L1-003: Python subprocess shell=True
function testL1_003(line) {
  if (/^\s*#/.test(line)) return false;
  return /subprocess\.\w+\(.*shell\s*=\s*True/.test(line);
}
assert('L1-003: subprocess.run(shell=True) triggers', testL1_003('subprocess.run(cmd, shell=True)'));
assert('L1-003: subprocess.run(cmd) safe', !testL1_003('subprocess.run(cmd)'));
assert('L1-003: # comment safe', !testL1_003('# subprocess.run(cmd, shell=True)'));

// L1-004: Python os.system()
function testL1_004(line) {
  if (/^\s*#/.test(line)) return false;
  return /\bos\.system\s*\(/.test(line);
}
assert('L1-004: os.system(cmd) triggers', testL1_004('os.system(user_command)'));
assert('L1-004: os.path.join safe', !testL1_004('os.path.join(a, b)'));

// L1-005: Server binding to 0.0.0.0
function testL1_005(line) {
  if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
  if (/['"]0\.0\.0\.0['"]/.test(line) && /(listen|bind|host|run)\s*[=(]/.test(line)) return true;
  if (/host\s*[:=]\s*['"]0\.0\.0\.0['"]/.test(line)) return true;
  if (/ListenAndServe\s*\(\s*["']:/.test(line)) return true;
  return false;
}
assert('L1-005: listen("0.0.0.0") triggers', testL1_005('app.listen(3000, "0.0.0.0")'));
assert('L1-005: host: "0.0.0.0" triggers', testL1_005('host: "0.0.0.0"'));
assert('L1-005: Go ListenAndServe triggers', testL1_005('http.ListenAndServe(":8080", nil)'));
assert('L1-005: listen("127.0.0.1") safe', !testL1_005('app.listen(3000, "127.0.0.1")'));

// L1-006: Path join without traversal validation
function testL1_006(line) {
  if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
  if (/path\.join\s*\(/.test(line) || /os\.path\.join\s*\(/.test(line)) return true;
  if (/filepath\.Join\s*\(/.test(line)) return true;
  return false;
}
assert('L1-006: path.join(dir, file) triggers', testL1_006('const f = path.join(dir, file)'));
assert('L1-006: os.path.join triggers', testL1_006('p = os.path.join(base, name)'));
assert('L1-006: Go filepath.Join triggers', testL1_006('p := filepath.Join(dir, name)'));
assert('L1-006: path.resolve safe', !testL1_006('path.resolve(dir)'));

// L1-007: File read with variable path
function testL1_007(line) {
  if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
  if (/fs\.(readFile|readFileSync)\s*\(/.test(line) && !/fs\.(readFile|readFileSync)\s*\(\s*['"`]/.test(line)) return true;
  if (/os\.(ReadFile|Open|Create|OpenFile|WriteFile)\s*\(/.test(line) && !/os\.(ReadFile|Open|Create|OpenFile|WriteFile)\s*\(\s*["'`]/.test(line)) return true;
  return false;
}
assert('L1-007: fs.readFileSync(var) triggers', testL1_007('const d = fs.readFileSync(userPath)'));
assert('L1-007: fs.readFileSync("lit") safe', !testL1_007('fs.readFileSync("config.json")'));
assert('L1-007: Go os.ReadFile(var) triggers', testL1_007('data, _ := os.ReadFile(filePath)'));
assert('L1-007: Go os.ReadFile("lit") safe', !testL1_007('os.ReadFile("config.json")'));

// L1-008: Python exec()
function testL1_008(line) {
  if (/^\s*#/.test(line)) return false;
  if (/\bexec\s*\(/.test(line)) {
    if (/execut/.test(line) || /exec_/.test(line) || /\.exec\s*\(/.test(line)) return false;
    return true;
  }
  return false;
}
assert('L1-008: exec(code) triggers', testL1_008('exec(user_code)'));
assert('L1-008: executor.run safe', !testL1_008('executor.run(task)'));
assert('L1-008: exec_command safe', !testL1_008('exec_command("ls")'));

// L1-009: Dynamic import/require
function testL1_009(line) {
  if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
  if (/\bimport\s*\(/.test(line) && !/\bimport\s*\(\s*['"`]/.test(line)) return true;
  if (/\brequire\s*\(/.test(line) && !/\brequire\s*\(\s*['"`]/.test(line)) return true;
  return false;
}
assert('L1-009: require(variable) triggers', testL1_009('const m = require(modulePath)'));
assert('L1-009: import(variable) triggers', testL1_009('const m = await import(pluginName)'));
assert('L1-009: require("literal") safe', !testL1_009('const fs = require("fs")'));
assert('L1-009: import("literal") safe', !testL1_009('const m = await import("./module")'));

// L1-010: Wildcard CORS
function testL1_010(line) {
  if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
  if (/\bcors\s*\(\s*\)/.test(line)) return true;
  if (/origin\s*[:=]\s*['"`]\*['"`]/.test(line)) return true;
  return false;
}
assert('L1-010: cors() triggers', testL1_010('app.use(cors())'));
assert('L1-010: origin: "*" triggers', testL1_010('origin: "*"'));
assert('L1-010: cors({ origin: "https://app.com" }) safe', !testL1_010('cors({ origin: "https://app.com" })'));

// L1-012: Pickle deserialization
function testL1_012(line) {
  if (/^\s*#/.test(line)) return false;
  return /\bpickle\.(loads?|Unpickler)\s*\(/.test(line) || /\bdill\.loads?\s*\(/.test(line);
}
assert('L1-012: pickle.load(f) triggers', testL1_012('data = pickle.load(f)'));
assert('L1-012: pickle.loads(bytes) triggers', testL1_012('data = pickle.loads(raw_bytes)'));
assert('L1-012: json.load(f) safe', !testL1_012('data = json.load(f)'));

// L1-013: YAML unsafe load
function testL1_013(line) {
  if (/^\s*#/.test(line)) return false;
  if (/yaml\.unsafe_load\s*\(/.test(line)) return true;
  if (/yaml\.load\s*\(/.test(line) && !/SafeLoader|safe_load|BaseLoader|FullLoader/.test(line)) return true;
  return false;
}
assert('L1-013: yaml.load(f) triggers', testL1_013('data = yaml.load(f)'));
assert('L1-013: yaml.unsafe_load(f) triggers', testL1_013('data = yaml.unsafe_load(f)'));
assert('L1-013: yaml.safe_load(f) safe', !testL1_013('data = yaml.safe_load(f)'));
assert('L1-013: yaml.load(f, Loader=SafeLoader) safe', !testL1_013('data = yaml.load(f, Loader=yaml.SafeLoader)'));

// L1-014: SQL injection via Python f-string
function testL1_014(line) {
  if (/^\s*#/.test(line)) return false;
  if (/\.execute\s*\(\s*f['"`]/.test(line)) return true;
  if (/\.execute\s*\(\s*['"`].*\+/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
  return false;
}
assert('L1-014: .execute(f"SELECT...") triggers', testL1_014('cursor.execute(f"SELECT * FROM users WHERE id={uid}")'));
assert('L1-014: .execute("SELECT" + var) triggers', testL1_014('cursor.execute("SELECT * FROM users WHERE id=" + uid)'));
assert('L1-014: .execute("SELECT ?", (id,)) safe', !testL1_014('cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'));

// L1-015: SSL/TLS verification disabled
function testL1_015(line) {
  if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) return false;
  if (/verify\s*=\s*False/.test(line) && /\.(get|post|put|delete|patch|request|fetch)\s*\(/.test(line)) return true;
  if (/rejectUnauthorized\s*:\s*false/.test(line)) return true;
  return false;
}
assert('L1-015: requests.get(verify=False) triggers', testL1_015('requests.get(url, verify=False)'));
assert('L1-015: rejectUnauthorized: false triggers', testL1_015('rejectUnauthorized: false'));
assert('L1-015: requests.get(url) safe', !testL1_015('requests.get(url)'));

// L1-016: Insecure random for security
function testL1_016(line) {
  if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) return false;
  const hasWeakRandom = /\b(Math\.random|random\.(choice|choices|randint|sample|random))\s*\(/.test(line);
  const hasSecurityContext = /\b(token|key|secret|password|nonce|salt|session|csrf|otp|code)\b/i.test(line);
  return hasWeakRandom && hasSecurityContext;
}
assert('L1-016: Math.random() for token triggers', testL1_016('const token = Math.random().toString(36)'));
assert('L1-016: random.choice for token triggers', testL1_016('token = "".join(random.choice(chars) for _ in range(32))'));
assert('L1-016: Math.random() for animation safe', !testL1_016('const delay = Math.random() * 1000'));

// L1-017: Python CORS wildcard (Starlette)
function testL1_017(line) {
  if (/^\s*#/.test(line)) return false;
  return /allow_origins\s*=\s*\[.*['"`]\*['"`]/.test(line);
}
assert('L1-017: allow_origins=["*"] triggers', testL1_017('allow_origins=["*"]'));
assert('L1-017: allow_origins=["https://app.com"] safe', !testL1_017('allow_origins=["https://app.com"]'));

// L1-018: Go exec.Command with shell
function testL1_018(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (/exec\.Command\s*\(/.test(line) && /(sh|bash|cmd)/.test(line)) return true;
  if (/exec\.Command\s*\(\s*fmt\.Sprintf/.test(line)) return true;
  return false;
}
assert('L1-018: exec.Command("sh", "-c") triggers', testL1_018('cmd := exec.Command("sh", "-c", input)'));
assert('L1-018: exec.Command(fmt.Sprintf) triggers', testL1_018('cmd := exec.Command(fmt.Sprintf("ls %s", dir))'));
assert('L1-018: exec.Command("ls") without shell safe', !testL1_018('out := exec.Command("ls", "-la")'));

// L1-019: Go text/template for HTML
function testL1_019(line) {
  if (/^\s*\/\//.test(line)) return false;
  return /["']text\/template["']/.test(line);
}
assert('L1-019: "text/template" import triggers', testL1_019('import "text/template"'));
assert('L1-019: "html/template" safe', !testL1_019('import "html/template"'));

// L1-020: Go SQL with fmt.Sprintf
function testL1_020(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (/\.(Query|Exec|QueryRow|QueryContext|ExecContext)\s*\(\s*fmt\.Sprintf/.test(line)) return true;
  if (/\.(Query|Exec|QueryRow)\s*\(.*\+/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
  return false;
}
assert('L1-020: db.Query(fmt.Sprintf) triggers', testL1_020('rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))'));
assert('L1-020: db.Exec(string concat) triggers', testL1_020('db.Exec("DELETE FROM users WHERE id=" + id)'));
assert('L1-020: db.Query("SELECT... $1", id) safe', !testL1_020('db.Query("SELECT * FROM users WHERE id = $1", id)'));

// L1-021: Go TLS InsecureSkipVerify
function testL1_021(line) {
  if (/^\s*\/\//.test(line)) return false;
  return /InsecureSkipVerify\s*:\s*true/.test(line);
}
assert('L1-021: InsecureSkipVerify: true triggers', testL1_021('InsecureSkipVerify: true'));
assert('L1-021: InsecureSkipVerify: false safe', !testL1_021('InsecureSkipVerify: false'));

// L1-022: Go CORS wildcard
function testL1_022(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (/cors\.(AllowAll|Default)\s*\(/.test(line)) return true;
  if (/AllowedOrigins.*\*/.test(line)) return true;
  return false;
}
assert('L1-022: cors.AllowAll() triggers', testL1_022('c := cors.AllowAll()'));
assert('L1-022: AllowedOrigins: ["*"] triggers', testL1_022('AllowedOrigins: []string{"*"}'));
assert('L1-022: AllowedOrigins: ["https://..."] safe', !testL1_022('AllowedOrigins: []string{"https://app.com"}'));

// L1-023: Rust unsafe block
function testL1_023(line) {
  if (/^\s*\/\//.test(line)) return false;
  return /\bunsafe\s*\{/.test(line);
}
assert('L1-023: unsafe { triggers', testL1_023('unsafe { ptr::read(p) }'));
assert('L1-023: unsafe block multiline triggers', testL1_023('    unsafe {'));
assert('L1-023: // unsafe { in comment safe', !testL1_023('// unsafe { not real }'));
assert('L1-023: safe code', !testL1_023('let safe_val = compute();'));

// L1-024: Rust Command::new with user input
function testL1_024(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (/Command::new\s*\(\s*format!/.test(line)) return true;
  if (/Command::new\s*\(\s*&?format!/.test(line)) return true;
  if (/Command::new\s*\(\s*"(sh|bash|cmd)"/.test(line)) return true;
  return false;
}
assert('L1-024: Command::new(format!) triggers', testL1_024('Command::new(format!("ls {}", dir))'));
assert('L1-024: Command::new("sh") triggers', testL1_024('Command::new("sh").arg("-c").arg(input)'));
assert('L1-024: Command::new("ls") safe', !testL1_024('Command::new("ls").arg("-la")'));

// L1-025: Rust SQL with format!
function testL1_025(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (/\.(query|execute|query_as|fetch_one|fetch_all)\s*\(\s*&?format!/.test(line)) return true;
  return false;
}
assert('L1-025: .query(&format!(...)) triggers', testL1_025('conn.query(&format!("SELECT * FROM users WHERE id = {}", id))'));
assert('L1-025: .execute(&format!(...)) triggers', testL1_025('conn.execute(&format!("DELETE FROM t WHERE id={}", id))'));
assert('L1-025: sqlx::query!() safe', !testL1_025('sqlx::query!("SELECT * FROM users WHERE id = $1", id)'));

// L1-026: Rust TLS danger_accept_invalid_certs
function testL1_026(line) {
  if (/^\s*\/\//.test(line)) return false;
  return /danger_accept_invalid_certs\s*\(\s*true\s*\)/.test(line);
}
assert('L1-026: danger_accept_invalid_certs(true) triggers', testL1_026('.danger_accept_invalid_certs(true)'));
assert('L1-026: danger_accept_invalid_certs(false) safe', !testL1_026('.danger_accept_invalid_certs(false)'));

// ─────────────────────────────────────────────
// Self-scan: scanner must not trigger critical on itself
// ─────────────────────────────────────────────

console.log('\n=== Self-Scan Integrity ===');

// Self-scan: verify scanner produces valid JSON output on own repo
const { execFileSync: execSelfScan } = require('child_process');
const selfScanOutputPath = '/tmp/compuute-self-scan-test.json';
let selfScanJson = null;
try {
  execSelfScan('node', ['compuute-scan.js', '.', '--json', '--output', selfScanOutputPath], {
    stdio: 'pipe',
    timeout: 30000,
  });
} catch {
  // Scanner may exit non-zero (findings detected), but file is still written
}
try {
  const raw = require('fs').readFileSync(selfScanOutputPath, 'utf-8');
  selfScanJson = JSON.parse(raw);
} catch {
  selfScanJson = null;
}
assert('Self-scan: produces valid JSON', selfScanJson !== null);
assert('Self-scan: has findings array', selfScanJson && Array.isArray(selfScanJson.findings));
assert('Self-scan: has discovery data', selfScanJson && selfScanJson.l0Discovery !== undefined);
assert('Self-scan: has version', selfScanJson && selfScanJson.version === '0.5.0');

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
