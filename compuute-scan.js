#!/usr/bin/env node
// compuute-scan v0.1.0 — MCP Server Security Scanner
// Internal tool for Compuute AB | daniel@compuute.se
// Zero external dependencies. Node.js built-ins only.

'use strict';

const fs = require('fs');
const path = require('path');

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const VERSION = '0.3.0';
const MAX_FILE_SIZE = 500 * 1024; // 500 KB
const GUARD_WINDOW = 15; // lines above/below to check for guards

const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.py', '.mjs', '.cjs', '.tsx', '.jsx', '.go',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  'coverage', '.turbo', '.next', '.venv', 'venv', 'vendor',
]);

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ─────────────────────────────────────────────
// CLI Argument Parsing
// ─────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    repoPath: null,
    output: null,
    json: false,
    sarif: false,
    verbose: false,
    layer: null,    // filter by layer e.g. "L1"
    minSeverity: null,
    failOnSeverity: null,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--help' || a === '-h') { opts.help = true; }
    else if (a === '--json') { opts.json = true; }
    else if (a === '--sarif') { opts.sarif = true; }
    else if (a === '--verbose' || a === '-v') { opts.verbose = true; }
    else if (a === '--output' || a === '-o') { opts.output = args[++i]; }
    else if (a === '--layer') { opts.layer = args[++i]?.toUpperCase(); }
    else if (a === '--min-severity') { opts.minSeverity = args[++i]?.toLowerCase(); }
    else if (a === '--fail-on-severity') { opts.failOnSeverity = args[++i]?.toLowerCase(); }
    else if (!a.startsWith('-')) { opts.repoPath = a; }
  }

  return opts;
}

function printUsage() {
  console.log(`
compuute-scan v${VERSION} — MCP Server Security Scanner
Compuute AB | Internal Tool

Usage:
  compuute-scan <repo-path> [options]

Options:
  --output <file>         Write report to file
  --json                  Output JSON instead of markdown
  --sarif                 Output SARIF (GitHub Code Scanning)
  --verbose               Show files being scanned
  --layer <L0-L4>         Filter findings by layer
  --min-severity <s>      Filter: critical, high, medium, low
  --fail-on-severity <s>  Exit code 1 if findings >= severity (for CI)
  --help                  Show this message

Exit codes:
  0  No findings (or below --fail-on-severity threshold)
  1  Findings at or above --fail-on-severity threshold
  2  Scanner error (invalid path, etc.)

Examples:
  compuute-scan ./my-mcp-server
  compuute-scan ./server --output report.md
  compuute-scan ./server --json --output report.json
  compuute-scan ./server --sarif --output report.sarif
  compuute-scan ./server --layer L1 --min-severity high
  compuute-scan ./server --fail-on-severity high
`);
}

// ─────────────────────────────────────────────
// File Walker
// ─────────────────────────────────────────────

function walkDir(dir) {
  const files = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkDir(full));
    } else if (entry.isFile() && SCAN_EXTENSIONS.has(path.extname(entry.name))) {
      try {
        const stat = fs.statSync(full);
        if (stat.size <= MAX_FILE_SIZE) {
          files.push(full);
        }
      } catch {
        // skip unreadable
      }
    }
  }
  return files;
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
// Guard Check System
// ─────────────────────────────────────────────

/**
 * Checks if there's a mitigation/guard pattern within GUARD_WINDOW
 * lines above or below the matched line.
 * Returns { mitigated: bool, guardLine: number|null, guardCode: string|null }
 */
function checkGuard(lines, matchLineIdx, guardPatterns) {
  const start = Math.max(0, matchLineIdx - GUARD_WINDOW);
  const end = Math.min(lines.length - 1, matchLineIdx + GUARD_WINDOW);

  for (let i = start; i <= end; i++) {
    if (i === matchLineIdx) continue;
    const line = lines[i];
    for (const gp of guardPatterns) {
      if (gp.test(line)) {
        return {
          mitigated: true,
          guardLine: i + 1,
          guardCode: line.trim().substring(0, 120),
        };
      }
    }
  }
  return { mitigated: false, guardLine: null, guardCode: null };
}

function downgradeSeverity(severity) {
  const map = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
  return map[severity] || severity;
}

// ─────────────────────────────────────────────
// Security Rules — L1: SANDBOXING
// ─────────────────────────────────────────────

const L1_RULES = [
  {
    id: 'L1-001',
    title: 'eval() with non-literal argument',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'eval() executes arbitrary code. If the argument is user-controlled, an attacker can execute arbitrary commands.',
    recommendation: 'Replace eval() with a safe parser or template engine. For JSON, use JSON.parse(). For math, use a sandboxed expression evaluator.',
    // Match eval( but not in comments
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // JS/Python eval — flag all eval() except eval('literal') with simple quotes
      // Template literals (backticks) with interpolation ARE dangerous
      if (!/\beval\s*\(/.test(line)) return false;
      // Only exclude eval('...') or eval("...") with simple string literals
      if (/\beval\s*\(\s*['"]/.test(line)) return false;
      return true;
    },
    guards: [/JSON\.parse/, /safeEval/, /sandbox/, /restricted/i],
  },
  {
    id: 'L1-002',
    title: 'Shell command execution (exec/spawn)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'exec/execSync/spawn can execute arbitrary shell commands. Use execFile with explicit arguments instead.',
    recommendation: 'Use child_process.execFile() or spawn() with an argument array (no shell interpolation). Never pass user input to exec().',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Exclude regex.exec(), mongoose .exec(), promise .exec(), query.exec()
      if (/\.exec\s*\(/.test(line)) {
        // Only flag child_process exec patterns
        if (/\bexec\s*\(/.test(line) && !/\w\.exec\s*\(/.test(line)) return true;
        return false;
      }
      if (/\bexecSync\s*\(/.test(line)) return true;
      if (/\bspawn\s*\(/.test(line) && /['"`]/.test(line)) {
        // spawn with string arg (not array)
        return true;
      }
      return false;
    },
    guards: [/execFile/, /escapeshell/i, /sanitize/i, /whitelist/i, /allowlist/i],
  },
  {
    id: 'L1-003',
    title: 'Python subprocess with shell=True',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'subprocess with shell=True passes commands through the system shell, enabling command injection.',
    recommendation: 'Use subprocess.run() with a list of arguments and shell=False (the default).',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      return /subprocess\.\w+\(.*shell\s*=\s*True/.test(line);
    },
    guards: [/shlex\.quote/, /shlex\.split/, /shell\s*=\s*False/],
  },
  {
    id: 'L1-004',
    title: 'Python os.system() call',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'os.system() executes commands through the system shell with no input sanitization.',
    recommendation: 'Use subprocess.run() with explicit argument lists instead of os.system().',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      return /\bos\.system\s*\(/.test(line);
    },
    guards: [/subprocess/, /shlex/],
  },
  {
    id: 'L1-005',
    title: 'Server binding to 0.0.0.0 (all interfaces)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'Binding to 0.0.0.0 exposes the server on all network interfaces, making it accessible from any network.',
    recommendation: 'Bind to 127.0.0.1 (localhost) unless external access is explicitly required. Use a reverse proxy for public exposure.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      if (/['"]0\.0\.0\.0['"]/.test(line) && /(listen|bind|host|run)\s*[=(]/.test(line)) return true;
      if (/host\s*[:=]\s*['"]0\.0\.0\.0['"]/.test(line)) return true;
      // Go: ListenAndServe(":port", ...) — binds all interfaces
      if (/ListenAndServe\s*\(\s*["']:/.test(line)) return true;
      if (/net\.Listen\s*\(\s*["']tcp["']\s*,\s*["'](0\.0\.0\.0)?:/.test(line)) return true;
      return false;
    },
    guards: [/reverse.?proxy/i, /nginx/i, /traefik/i, /behind.*proxy/i, /127\.0\.0\.1/, /localhost/],
  },
  {
    id: 'L1-006',
    title: 'Path join without traversal validation',
    layer: 'L1',
    severity: 'high',
    owasp: 'A01:2021 Broken Access Control',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).',
    recommendation: 'Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      if (/path\.join\s*\(/.test(line) || /os\.path\.join\s*\(/.test(line)) return true;
      // Go: filepath.Join
      if (/filepath\.Join\s*\(/.test(line)) return true;
      return false;
    },
    guards: [
      /startsWith/, /realpath/, /resolve/, /includes\s*\(\s*['"]\.\.['"]/,
      /throw/, /reject/, /Error/, /normalize/, /is_relative_to/,
      /commonpath/, /abspath/,
      // Go-specific guards
      /filepath\.Abs/, /filepath\.Clean/, /filepath\.Rel/,
      /strings\.HasPrefix/, /EvalSymlinks/, /filepath\.Base/,
    ],
  },
  {
    id: 'L1-007',
    title: 'File read with variable path (no validation)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A01:2021 Broken Access Control',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Reading files with a user-controlled path without validation enables arbitrary file read attacks.',
    recommendation: 'Validate the resolved path starts with the expected base directory. Use a whitelist of allowed paths if possible.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // fs.readFile/readFileSync with a variable (not a literal string)
      if (/fs\.(readFile|readFileSync)\s*\(/.test(line) && !/fs\.(readFile|readFileSync)\s*\(\s*['"`]/.test(line)) return true;
      // Python open() with variable path
      if (/\bopen\s*\(/.test(line) && !/\bopen\s*\(\s*['"]/.test(line) && !/\.open\s*\(/.test(line)) {
        // Avoid matching things like file.open(), db.open()
        if (/^[^.]*\bopen\s*\(/.test(line.trim())) return true;
      }
      // Go: os.ReadFile, os.Open, os.Create with variable path
      if (/os\.(ReadFile|Open|Create|OpenFile|WriteFile)\s*\(/.test(line) && !/os\.(ReadFile|Open|Create|OpenFile|WriteFile)\s*\(\s*["'`]/.test(line)) return true;
      // Go: ioutil.ReadFile with variable
      if (/ioutil\.ReadFile\s*\(/.test(line) && !/ioutil\.ReadFile\s*\(\s*["'`]/.test(line)) return true;
      return false;
    },
    guards: [
      /startsWith/, /realpath/, /resolve/, /includes\s*\(\s*['"]\.\.['"]/,
      /throw/, /reject/, /Error/, /whitelist/i, /allowlist/i, /allowedPaths/i,
      /filepath\.Abs/, /filepath\.Clean/, /strings\.HasPrefix/, /EvalSymlinks/,
    ],
  },
  {
    id: 'L1-008',
    title: 'Python exec() — arbitrary code execution',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'exec() executes arbitrary Python code. If user input reaches exec(), it enables full code execution.',
    recommendation: 'Avoid exec(). Use ast.literal_eval() for safe data parsing or a restricted execution environment.',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      // Python exec() but not executor/execute/exec_command etc.
      if (/\bexec\s*\(/.test(line)) {
        // Exclude: executor, execute, exec_command, .exec(
        if (/execut/.test(line) || /exec_/.test(line) || /\.exec\s*\(/.test(line)) return false;
        return true;
      }
      return false;
    },
    guards: [/ast\.literal_eval/, /restricted/i, /sandbox/i],
  },
  {
    id: 'L1-009',
    title: 'Dynamic import/require with variable path',
    layer: 'L1',
    severity: 'high',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Dynamic import() or require() with a variable argument allows loading arbitrary modules at runtime. An attacker who controls the path can load malicious code.',
    recommendation: 'Use static imports or maintain an explicit allowlist of permitted module paths. Validate and sanitize any dynamic paths against a whitelist.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // import(variable) — not import('literal')
      if (/\bimport\s*\(/.test(line) && !/\bimport\s*\(\s*['"`]/.test(line)) return true;
      // require(variable) — not require('literal')
      if (/\brequire\s*\(/.test(line) && !/\brequire\s*\(\s*['"`]/.test(line)) return true;
      return false;
    },
    guards: [/allowlist/i, /whitelist/i, /allowedModules/i, /safeRequire/i, /validateModule/i],
  },
  {
    id: 'L1-010',
    title: 'Wildcard CORS origin (Access-Control-Allow-Origin: *)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'Setting Access-Control-Allow-Origin to "*" allows any website to make cross-origin requests to this MCP server. Combined with credentials, this enables cross-site data theft.',
    recommendation: 'Restrict CORS to specific trusted origins. Never use wildcard CORS on authenticated endpoints. Use an allowlist of permitted origins.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // cors({ origin: '*' }) or cors() with no args (defaults to *)
      if (/\bcors\s*\(\s*\)/.test(line)) return true;
      if (/origin\s*[:=]\s*['"`]\*['"`]/.test(line)) return true;
      // Access-Control-Allow-Origin header set to *
      if (/['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]/.test(line)) return true;
      if (/['"]\*['"]\s*\)/.test(line) && /setHeader|header\s*\(/.test(line) && /Access.Control.Allow.Origin/.test(line)) return true;
      return false;
    },
    guards: [/allowedOrigins/i, /originWhitelist/i, /corsOptions/i, /origin.*!==.*\*/, /validateOrigin/i],
  },
  {
    id: 'L1-012',
    title: 'Pickle deserialization (arbitrary code execution)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'pickle.load/loads deserializes arbitrary Python objects and can execute code during unpickling. An attacker who controls the input can achieve full remote code execution.',
    recommendation: 'Never unpickle untrusted data. Use json, msgpack, or protobuf instead. If pickle is required, use hmac-signed payloads and restrict classes via RestrictedUnpickler.',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      return /\bpickle\.(loads?|Unpickler)\s*\(/.test(line) || /\bdill\.loads?\s*\(/.test(line) || /\bmarshal\.loads?\s*\(/.test(line);
    },
    guards: [/hmac/i, /RestrictedUnpickler/i, /json\.loads/i, /verify.*signature/i, /trusted/i],
  },
  {
    id: 'L1-013',
    title: 'YAML unsafe load (code execution)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'yaml.load() without SafeLoader can instantiate arbitrary Python objects, leading to remote code execution. yaml.unsafe_load() is explicitly dangerous.',
    recommendation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). Never use yaml.load() with untrusted input without specifying a safe Loader.',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      if (/yaml\.unsafe_load\s*\(/.test(line)) return true;
      // yaml.load( without SafeLoader/safe_load
      if (/yaml\.load\s*\(/.test(line) && !/SafeLoader|safe_load|BaseLoader|FullLoader/.test(line)) return true;
      return false;
    },
    guards: [/safe_load/, /SafeLoader/, /BaseLoader/],
  },
  {
    id: 'L1-014',
    title: 'SQL injection via Python f-string or format',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Building SQL queries with f-strings, %-formatting, or string concatenation allows SQL injection when user input is interpolated directly into the query.',
    recommendation: 'Use parameterized queries: cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,)). With ORMs, use the query builder instead of raw SQL strings.',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      // cursor.execute(f"...") or .execute(f"...")
      if (/\.execute\s*\(\s*f['"`]/.test(line)) return true;
      // cursor.execute("..." % var) — %-formatting
      if (/\.execute\s*\(\s*['"`].*%s/.test(line) && /%\s*\(/.test(line)) return true;
      // cursor.execute("..." + var + "...")
      if (/\.execute\s*\(\s*['"`].*\+/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
      return false;
    },
    guards: [/parameterized/i, /prepared/i, /placeholder/i, /\?\s*,/, /%s.*,\s*\(/, /sqlalchemy/i],
  },
  {
    id: 'L1-015',
    title: 'SSL/TLS verification disabled',
    layer: 'L1',
    severity: 'high',
    owasp: 'A02:2021 Cryptographic Failures',
    nis2: 'Art. 21(2)(h) — Cryptography and encryption',
    description: 'Disabling SSL/TLS certificate verification (verify=False, ssl=False) allows man-in-the-middle attacks. All outbound HTTPS connections should validate certificates.',
    recommendation: 'Remove verify=False / ssl=False. Use proper CA certificates (certifi). If using self-signed certs in development, restrict to dev environments only.',
    test: (line) => {
      if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) return false;
      // Python: verify=False
      if (/verify\s*=\s*False/.test(line) && /\.(get|post|put|delete|patch|request|fetch)\s*\(/.test(line)) return true;
      // Python aiohttp: ssl=False
      if (/ssl\s*=\s*False/.test(line)) return true;
      // Node.js: rejectUnauthorized: false
      if (/rejectUnauthorized\s*:\s*false/.test(line)) return true;
      // NODE_TLS_REJECT_UNAUTHORIZED = '0'
      if (/NODE_TLS_REJECT_UNAUTHORIZED/.test(line) && /['"`]0['"`]/.test(line)) return true;
      return false;
    },
    guards: [/certifi/i, /NODE_ENV.*production/i, /development/i, /process\.env\.NODE_TLS/],
  },
  {
    id: 'L1-016',
    title: 'Insecure random used for security purpose',
    layer: 'L1',
    severity: 'high',
    owasp: 'A02:2021 Cryptographic Failures',
    nis2: 'Art. 21(2)(h) — Cryptography and encryption',
    description: 'Using Math.random() (JS), Python random module, or Go math/rand for tokens, keys, or secrets produces predictable values. These PRNGs are not cryptographically secure.',
    recommendation: 'Use crypto.randomBytes/randomUUID (Node.js), secrets.token_hex (Python), or crypto/rand (Go) for any security-sensitive random values.',
    test: (line) => {
      if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) return false;
      const hasWeakRandom = /\b(Math\.random|random\.(choice|choices|randint|sample|random)|rand\.(Intn|Int31|Int63|Float64|Read))\s*\(/.test(line);
      const hasSecurityContext = /\b(token|key|secret|password|nonce|salt|session|csrf|otp|code)\b/i.test(line);
      return hasWeakRandom && hasSecurityContext;
    },
    guards: [/crypto\.randomBytes/, /crypto\.randomUUID/, /\bsecrets\./, /crypto\.getRandomValues/, /crypto\/rand/, /uuid/i],
  },
  {
    id: 'L1-017',
    title: 'Python CORS wildcard (Starlette/FastAPI)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'Setting allow_origins=["*"] in Starlette/FastAPI CORSMiddleware allows any website to make cross-origin requests to this MCP server.',
    recommendation: 'Restrict allow_origins to specific trusted domains. Never use wildcard CORS on MCP servers that handle authenticated requests.',
    test: (line) => {
      if (/^\s*#/.test(line)) return false;
      // allow_origins=["*"] or allow_origins=['*']
      if (/allow_origins\s*=\s*\[.*['"`]\*['"`]/.test(line)) return true;
      return false;
    },
    guards: [/allow_origins\s*=\s*\[.*(?!['"`]\*['"`])['"`]https?:/, /allowedOrigins/i, /CORS_ORIGINS/i],
  },
  {
    id: 'L1-018',
    title: 'Go exec.Command with string concatenation',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Using exec.Command with fmt.Sprintf or string concatenation enables shell injection if user input is interpolated. Go exec.Command does not use a shell by default, but passing concatenated strings to "/bin/sh -c" re-introduces the risk.',
    recommendation: 'Pass arguments as separate parameters to exec.Command (arg-per-slot). Never use fmt.Sprintf to build command strings. Avoid "/bin/sh", "-c" with user input.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // exec.Command with sh -c or bash -c
      if (/exec\.Command\s*\(/.test(line) && /(sh|bash|cmd)/.test(line)) return true;
      // exec.Command with fmt.Sprintf
      if (/exec\.Command\s*\(\s*fmt\.Sprintf/.test(line)) return true;
      // exec.CommandContext with shell
      if (/exec\.CommandContext\s*\(/.test(line) && /(sh|bash|cmd)/.test(line)) return true;
      return false;
    },
    guards: [/shellescape/i, /shlex/i, /safeCommand/i, /allowedCommands/i, /whitelist/i],
  },
  {
    id: 'L1-019',
    title: 'Go text/template used for HTML (XSS risk)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Go text/template does not escape HTML. If used to render web content, user input can inject arbitrary HTML/JavaScript (XSS).',
    recommendation: 'Use html/template instead of text/template for any HTML output. html/template provides contextual auto-escaping.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /["']text\/template["']/.test(line);
    },
    guards: [/html\/template/, /template\.HTMLEscapeString/, /bluemonday/i, /sanitize/i],
    contextCheck: (lines, idx) => {
      const start = Math.max(0, idx - 10);
      const end = Math.min(lines.length - 1, idx + 10);
      for (let i = start; i <= end; i++) {
        if (/\b(html|HTML|web|http|response|ResponseWriter|ServeHTTP)\b/.test(lines[i])) return true;
      }
      return false;
    },
  },
  {
    id: 'L1-020',
    title: 'Go SQL query with fmt.Sprintf (injection risk)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Building SQL queries with fmt.Sprintf or string concatenation in Go allows SQL injection when user input is interpolated.',
    recommendation: 'Use parameterized queries: db.Query("SELECT * FROM t WHERE id = $1", id). Use sqlx or GORM query builders for complex queries.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // db.Query/Exec/QueryRow with fmt.Sprintf
      if (/\.(Query|Exec|QueryRow|QueryContext|ExecContext)\s*\(\s*fmt\.Sprintf/.test(line)) return true;
      // db.Query with string concat (+)
      if (/\.(Query|Exec|QueryRow)\s*\(.*\+/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
      return false;
    },
    guards: [/\$\d/, /\?\s*,/, /squirrel/i, /sqlx\.Named/i, /Prepare\s*\(/, /parameterized/i],
  },
  {
    id: 'L1-021',
    title: 'Go TLS InsecureSkipVerify enabled',
    layer: 'L1',
    severity: 'high',
    owasp: 'A02:2021 Cryptographic Failures',
    nis2: 'Art. 21(2)(h) — Cryptography and encryption',
    description: 'Setting InsecureSkipVerify: true disables TLS certificate validation, enabling man-in-the-middle attacks on all outbound HTTPS connections.',
    recommendation: 'Remove InsecureSkipVerify: true. Use proper CA certificates. If using self-signed certs in development, restrict via build tags or environment checks.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /InsecureSkipVerify\s*:\s*true/.test(line);
    },
    guards: [/development/i, /testing/i, /\.env/i, /os\.Getenv/],
  },
  {
    id: 'L1-022',
    title: 'Go CORS wildcard (rs/cors or manual header)',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'Setting AllowedOrigins to ["*"] or AllowAll() in Go CORS middleware allows any website to make cross-origin requests.',
    recommendation: 'Restrict AllowedOrigins to specific trusted domains. Use cors.Options{AllowedOrigins: []string{"https://app.example.com"}}.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // cors.AllowAll() or cors.Default()
      if (/cors\.(AllowAll|Default)\s*\(/.test(line)) return true;
      // AllowedOrigins: []string{"*"}
      if (/AllowedOrigins.*\*/.test(line)) return true;
      // Manual header set
      if (/Set.*Header.*Access-Control-Allow-Origin.*\*/.test(line)) return true;
      return false;
    },
    guards: [/AllowedOrigins.*https?:/, /isAllowedOrigin/i, /originValidator/i],
  },
];

// Negative check rules for L1 (whole-codebase checks)
const L1_NEGATIVE_RULES = [
  {
    id: 'L1-011',
    title: 'No security headers middleware detected',
    layer: 'L1',
    severity: 'medium',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'No security headers middleware (helmet, secure-headers) or manual security header configuration was detected. HTTP-exposed MCP servers should set Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, and other protective headers.',
    recommendation: 'Add helmet (Node.js) or secure-headers middleware. At minimum set: Content-Security-Policy, X-Content-Type-Options: nosniff, Strict-Transport-Security, X-Frame-Options: DENY.',
    pattern: /\b(helmet|secureHeaders|secure.headers|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options|nosniff)\b/i,
  },
];

// ─────────────────────────────────────────────
// Security Rules — L2: AUTHORIZATION
// ─────────────────────────────────────────────

const L2_RULES = [
  {
    id: 'L2-001',
    title: 'Hardcoded API key / secret / token',
    layer: 'L2',
    severity: 'high',
    owasp: 'A07:2021 Identification and Authentication Failures',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    description: 'Secrets hardcoded in source code can be extracted by anyone with code access. Use environment variables or a secrets manager.',
    recommendation: 'Store secrets in environment variables (process.env / os.environ). Use a secrets manager (AWS SM, HashiCorp Vault) for production.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // key/secret/token/password followed by = or : and a string 20+ chars
      const m = line.match(/(key|secret|token|password|apiKey|api_key|API_KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*['"`]([^'"`]{20,})[`'"]/i);
      if (m) {
        const val = m[2];
        // Exclude obvious placeholders
        if (/^(your[_-]|xxx|placeholder|changeme|CHANGE|TODO|INSERT|REPLACE|<)/i.test(val)) return false;
        // Exclude process.env references
        if (/process\.env|os\.environ|getenv|os\.Getenv|viper\.Get/.test(line)) return false;
        return true;
      }
      return false;
    },
    guards: [/process\.env/, /os\.environ/, /getenv/, /os\.Getenv/, /viper/i, /godotenv/i, /envconfig/i, /vault/i, /secrets?\s*manager/i],
  },
  {
    id: 'L2-004',
    title: 'JWT without expiry check',
    layer: 'L2',
    severity: 'medium',
    owasp: 'A07:2021 Identification and Authentication Failures',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    description: 'JWT tokens without expiry can be used indefinitely if compromised.',
    recommendation: 'Always set expiresIn/exp when signing JWTs and verify expiry on the server side.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      return /jwt\.sign\s*\(/.test(line);
    },
    guards: [/expiresIn/, /\bexp\b/, /maxAge/, /expires/],
  },
  {
    id: 'L2-010',
    title: 'Hardcoded database connection string with credentials',
    layer: 'L2',
    severity: 'high',
    owasp: 'A07:2021 Identification and Authentication Failures',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    description: 'Database connection strings with embedded usernames and passwords in source code can be extracted by anyone with code access.',
    recommendation: 'Store connection strings in environment variables or a secrets manager. Use os.environ/process.env to load credentials at runtime.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // postgresql://user:pass@host, mongodb://user:pass@host, redis://:pass@host, mysql://user:pass@host
      const m = line.match(/(DATABASE_URL|MONGO_URI|REDIS_URL|DB_URL|DSN|CONNECTION_STRING|SQLALCHEMY_DATABASE_URI)\s*[:=]\s*['"`](.*?)['"`]/i);
      if (m && /\w+:\/\/\w+:\w+@/.test(m[2])) return true;
      // Inline connection strings without variable name
      if (/['"`](postgres(ql)?|mongodb(\+srv)?|mysql|redis):\/\/\w+:[^'"`\s]{4,}@/.test(line)) {
        if (/process\.env|os\.environ|getenv|BaseSettings/.test(line)) return false;
        return true;
      }
      return false;
    },
    guards: [/process\.env/, /os\.environ/, /os\.getenv/, /getenv/, /BaseSettings/i, /vault/i, /secrets?\s*manager/i],
  },
  {
    id: 'L2-011',
    title: 'JWT decoded without signature verification',
    layer: 'L2',
    severity: 'high',
    owasp: 'A07:2021 Identification and Authentication Failures',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    description: 'Decoding JWTs without verifying the signature allows attackers to forge tokens with arbitrary claims. This bypasses all authentication.',
    recommendation: 'Always verify JWT signatures. In Python: jwt.decode(token, key, algorithms=["HS256"]). Never set verify=False or options={"verify_signature": False}.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // Python: jwt.decode(..., verify=False) or options={"verify_signature": False}
      if (/jwt\.decode\s*\(/.test(line) && /verify\s*[=:]\s*False/.test(line)) return true;
      if (/jwt\.decode\s*\(/.test(line) && /verify_signature.*False/.test(line)) return true;
      // Node: jwt.decode (not jwt.verify) — decode doesn't verify
      if (/jwt\.decode\s*\(/.test(line) && !/jwt\.verify/.test(line)) {
        // Only flag if it looks like it's used for auth decisions
        if (/\b(auth|user|role|permission|admin|access)\b/i.test(line)) return true;
      }
      return false;
    },
    guards: [/jwt\.verify/, /algorithms\s*=/, /verify\s*=\s*True/, /verify_signature.*True/],
  },
  {
    id: 'L2-005',
    title: 'PII pattern stored or processed without redaction',
    layer: 'L2',
    severity: 'high',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    dora: 'Art. 6(8) — Data integrity and confidentiality',
    gdpr: 'Art. 5(1)(c) — Data minimisation; Art. 5(1)(e) — Storage limitation',
    description: 'Code stores, writes, or persists data matched by PII patterns (e.g., email, SSN, credit card) without redaction. GDPR Art. 5(1)(c) requires data minimisation — only process personal data that is strictly necessary.',
    recommendation: 'Apply PII redaction (masking, hashing, or tokenisation) before storing or transmitting user-provided text. Use a PII detection library or MCP PII tool (pii.redact) in the data pipeline.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Detect storing/writing/inserting data that matches PII field names without redaction nearby
      const hasPiiField = /\b(email|ssn|social.?security|tax.?id|credit.?card|card.?number|phone.?number|personal.?number|personnummer|passport.?number|iban|date.?of.?birth|national.?id)\b/i.test(line);
      const hasStorage = /\b(save|store|write|insert|put|push|append|create|update|set)\s*\(/i.test(line);
      if (hasPiiField && hasStorage) return true;
      // Direct DB writes with PII field names
      const hasDbOp = /\.(save|create|insert|update|upsert|findAndUpdate|bulkWrite|add)\s*\(/.test(line);
      if (hasPiiField && hasDbOp) return true;
      return false;
    },
    guards: [/redact/i, /mask/i, /anonymi[sz]e/i, /hash/i, /encrypt/i, /tokenize/i, /pii/i, /sanitize.*pii/i, /gdpr/i],
  },
  {
    id: 'L2-006',
    title: 'PII logged without masking',
    layer: 'L2',
    severity: 'high',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    nis2: 'Art. 21(2)(g) — Audit and monitoring',
    dora: 'Art. 6(8) — Data integrity and confidentiality',
    gdpr: 'Art. 5(1)(c) — Data minimisation; Art. 5(1)(f) — Integrity and confidentiality',
    description: 'PII fields are passed to logging functions without masking. Log files often have broader access than production databases, making unmasked PII a compliance risk under GDPR Art. 5(1)(f).',
    recommendation: 'Mask or redact PII before logging. Use structured logging with a PII-safe serialiser that automatically redacts sensitive fields.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      const hasPiiField = /\b(email|ssn|social.?security|tax.?id|credit.?card|card.?number|phone.?number|personnummer|passport.?number|iban|national.?id)\b/i.test(line);
      const hasLog = /\b(console\.(log|info|warn|error|debug)|logger?\.(log|info|warn|error|debug)|log\.(info|warn|error|debug)|logging\.(info|warn|error|debug)|print)\s*\(/i.test(line);
      return hasPiiField && hasLog;
    },
    guards: [/redact/i, /mask/i, /sanitize/i, /\*{3,}/, /pii/i, /scrub/i],
  },
  {
    id: 'L2-008',
    title: 'Weak cryptographic hash used for security purpose',
    layer: 'L2',
    severity: 'high',
    owasp: 'A02:2021 Cryptographic Failures',
    nis2: 'Art. 21(2)(h) — Cryptography and encryption',
    description: 'MD5 and SHA-1 are cryptographically broken. Using them for password hashing, token generation, or integrity checks enables collision and preimage attacks.',
    recommendation: 'Use SHA-256/SHA-3 for integrity checks. Use bcrypt, scrypt, or argon2 for password hashing. Never use MD5 or SHA-1 for any security-relevant purpose.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Node.js: createHash('md5') or createHash('sha1')
      if (/createHash\s*\(\s*['"`](md5|sha-?1)['"`]\s*\)/i.test(line)) return true;
      // Python: hashlib.md5( or hashlib.sha1(
      if (/hashlib\.(md5|sha1)\s*\(/.test(line)) return true;
      // Go: md5.New(), md5.Sum(), sha1.New(), sha1.Sum()
      if (/\b(md5|sha1)\.(New|Sum)\s*\(/.test(line)) return true;
      // Go: import "crypto/md5" or "crypto/sha1"
      if (/["']crypto\/(md5|sha1)["']/.test(line)) return true;
      // Direct MD5/SHA1 function calls
      if (/\b(md5|sha1)\s*\(/i.test(line) && !/^\s*(import|require|const|let|var|from)\b/.test(line)) return true;
      return false;
    },
    guards: [/sha256/i, /sha384/i, /sha512/i, /sha3/i, /bcrypt/i, /scrypt/i, /argon2/i, /pbkdf2/i, /checksum/i, /etag/i, /cache/i],
  },
  {
    id: 'L2-009',
    title: 'Data storage without TTL or retention policy',
    layer: 'L2',
    severity: 'medium',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    dora: 'Art. 6(8) — Data integrity and confidentiality',
    gdpr: 'Art. 5(1)(e) — Storage limitation',
    description: 'Data is written to a database or file store without a TTL, expiry, or retention policy. GDPR Art. 5(1)(e) requires that personal data is kept only as long as necessary for the purpose.',
    recommendation: 'Set a TTL or expiry on stored records. Implement a data retention policy with automatic cleanup (e.g., TTL indexes in MongoDB, EXPIRE in Redis, scheduled purge jobs).',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Database insert/create/save operations
      const hasDbWrite = /\.(save|create|insert|insertOne|insertMany|put|set|hset|rpush|lpush|sadd|zadd|write)\s*\(/.test(line);
      // File-based persistence
      const hasFileWrite = /\b(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(/.test(line);
      return hasDbWrite || hasFileWrite;
    },
    guards: [/ttl/i, /expir/i, /retention/i, /maxAge/i, /deleteAfter/i, /purge/i, /cleanup/i, /createdAt/i, /ttlIndex/i, /EXPIRE/],
    // Only flag if it looks like persistent storage (near DB/model/store context)
    contextCheck: (lines, idx) => {
      const start = Math.max(0, idx - 10);
      const end = Math.min(lines.length - 1, idx + 10);
      for (let i = start; i <= end; i++) {
        if (/\b(mongo|mongoose|sequelize|prisma|knex|redis|typeorm|drizzle|firebase|supabase|dynamodb|collection|model|repository|store|database|db)\b/i.test(lines[i])) return true;
      }
      return false;
    },
  },
];

// Negative check rules for L2 (whole-codebase checks)
const L2_NEGATIVE_RULES = [
  {
    id: 'L2-002',
    title: 'No authentication mechanism detected',
    layer: 'L2',
    severity: 'medium',
    owasp: 'A07:2021 Identification and Authentication Failures',
    nis2: 'Art. 21(2)(c) — Access control policies',
    description: 'No authentication mechanism was found in the codebase. MCP servers should authenticate clients to prevent unauthorized access.',
    recommendation: 'Implement authentication using JWT, OAuth, API keys, or another mechanism appropriate for your transport.',
    pattern: /\b(auth|authenticate|requireAuth|jwt|oauth|bearer|api[-_]?key|apiKey|token.*verify|verifyToken|passport|session|login|BearerAuthBackend|RequireAuthMiddleware|TokenVerifier|AuthConfig|google\.oauth2|AuthMiddleware|jwtauth|go-jwt|casbin)\b/i,
  },
  {
    id: 'L2-003',
    title: 'No RBAC / permission system detected',
    layer: 'L2',
    severity: 'medium',
    owasp: 'A01:2021 Broken Access Control',
    nis2: 'Art. 21(2)(c) — Access control policies',
    description: 'No role-based access control or permission system was found. Tools should be restricted based on user roles.',
    recommendation: 'Implement role-based tool access. Define which roles can invoke which tools. Use a deny-by-default policy.',
    pattern: /\b(role|permission|rbac|canAccess|authorize|isAllowed|filter.*tag|defaultDeny|access.*control)\b/i,
  },
  {
    id: 'L2-007',
    title: 'No PII detection or redaction mechanism detected',
    layer: 'L2',
    severity: 'medium',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(f) — Security in acquisition, development and maintenance',
    dora: 'Art. 6(8) — Data integrity and confidentiality',
    gdpr: 'Art. 5(1)(c) — Data minimisation; Art. 25 — Data protection by design and by default',
    description: 'No PII detection, redaction, or masking mechanism was found in the codebase. MCP servers that process user-provided text risk leaking personal data (names, emails, tax IDs, credit cards) in tool responses, logs, or downstream storage — violating GDPR Art. 5(1)(c) data minimisation and Art. 25 data protection by design.',
    recommendation: 'Integrate a PII redaction layer before storing or returning user-provided text. Options: (1) use an MCP PII server (pii.redact) in the pipeline, (2) add a library like presidio, pii-redactor, or dlp, (3) implement regex-based redaction for your jurisdiction\'s ID formats.',
    pattern: /\b(pii|redact|anonymi[sz]e|mask.*pii|scrub.*pii|data.?minimi[sz]|gdpr.*redact|personnummer|detect.*pii|pii.*detect|dlp|presidio|pii[-_]?redact)/i,
  },
];

// ─────────────────────────────────────────────
// Security Rules — L3: TOOL INTEGRITY
// ─────────────────────────────────────────────

const L3_RULES = [
  {
    id: 'L3-001',
    title: 'JSON.stringify as direct tool response',
    layer: 'L3',
    severity: 'high',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.',
    recommendation: 'Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      return /JSON\.stringify\s*\(/.test(line);
    },
    guards: [/Presenter/i, /schema/i, /\bpick\b/, /\bomit\b/, /redact/i, /sanitize/i, /toJSON/],
    // Check 5-line window for content/text/return to confirm it's a response
    contextCheck: (lines, idx) => {
      const start = Math.max(0, idx - 5);
      const end = Math.min(lines.length - 1, idx + 5);
      for (let i = start; i <= end; i++) {
        if (/\bcontent\b|\btext\b|\breturn\b|\bresponse\b/.test(lines[i])) return true;
      }
      return false;
    },
  },
  {
    id: 'L3-003',
    title: 'Tool description exceeds 200 characters',
    layer: 'L3',
    severity: 'medium',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Excessively long tool descriptions can be used to inject hidden instructions for the LLM (prompt injection via tool metadata).',
    recommendation: 'Keep tool descriptions concise (<200 chars). Review long descriptions for embedded instructions or misleading content.',
    test: (line) => {
      const m = line.match(/description\s*[:=]\s*['"`](.{200,})[`'"]/);
      if (m) return true;
      // Also check template literal descriptions
      const m2 = line.match(/description\s*[:=]\s*`(.{200,})`/);
      return !!m2;
    },
    guards: [],
  },
  {
    id: 'L3-004',
    title: 'HTTP request to user-controlled URL (SSRF)',
    layer: 'L3',
    severity: 'high',
    owasp: 'A10:2021 Server-Side Request Forgery',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Making HTTP requests to user-supplied URLs enables Server-Side Request Forgery. Attackers can probe internal networks.',
    recommendation: 'Validate and whitelist allowed URLs/domains. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x).',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // fetch, axios, requests.get/post with a variable (not literal URL)
      if (/\bfetch\s*\(/.test(line) && !/\bfetch\s*\(\s*['"`]http/.test(line)) return true;
      if (/axios\.(get|post|put|delete|request)\s*\(/.test(line) && !/axios\.\w+\s*\(\s*['"`]http/.test(line)) return true;
      if (/requests\.(get|post|put|delete)\s*\(/.test(line) && !/requests\.\w+\s*\(\s*['"`]http/.test(line)) return true;
      if (/httpx\.(get|post|put|delete)\s*\(/.test(line) && !/httpx\.\w+\s*\(\s*['"`]http/.test(line)) return true;
      return false;
    },
    guards: [/whitelist/i, /allowlist/i, /allowedUrl/i, /allowedHost/i, /validateUrl/i, /isPrivateIp/i, /block.*private/i],
  },
  {
    id: 'L3-005',
    title: 'SQL string concatenation (injection risk)',
    layer: 'L3',
    severity: 'high',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Concatenating user input into SQL queries enables SQL injection attacks.',
    recommendation: 'Use parameterized queries (prepared statements) or an ORM. Never concatenate user input into SQL strings.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // Require SQL keywords in a SQL-specific context
      // SELECT must be followed by SQL tokens (*, FROM, column patterns)
      // INSERT must be followed by INTO
      // UPDATE must be followed by SET or table name pattern
      // DELETE must be followed by FROM
      const sqlPatterns = [
        /SELECT\s+(\*|[\w.]+\s*,|\w+\s+FROM)\s/,
        /INSERT\s+INTO\s/,
        /UPDATE\s+\w+\s+SET\s/,
        /DELETE\s+FROM\s/,
      ];
      const hasSql = sqlPatterns.some(p => p.test(line));
      if (!hasSql) return false;
      // Check for concatenation (+) or template literal with variable
      if (/\+\s*\w/.test(line) || /\$\{/.test(line) || /f['"].*\{/.test(line) || /%s/.test(line)) return true;
      return false;
    },
    guards: [/parameterized/i, /prepared/i, /placeholder/, /\$\d/, /\?/, /bind/i],
  },
  {
    id: 'L3-006',
    title: 'SKILL.md loaded without integrity check',
    layer: 'L3',
    severity: 'medium',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Loading skill definitions without hash verification allows tampering with tool behavior.',
    recommendation: 'Verify SKILL.md file integrity using a cryptographic hash (SHA-256) before loading.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      return (/readFile.*skill/i.test(line) || /loadSkill/i.test(line) || /SKILL\.md/i.test(line));
    },
    guards: [/verify/i, /hash/i, /integrity/i, /sha256/i, /checksum/i, /crypto/i],
  },
  {
    id: 'L3-007',
    title: 'Prompt injection in tool description',
    layer: 'L3',
    severity: 'high',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Tool descriptions containing instruction-like patterns (e.g., "ignore previous", "system:", hidden directives) can manipulate LLM behavior via prompt injection.',
    recommendation: 'Keep tool descriptions factual and short. Never embed instructions, system prompts, or behavioral directives in tool metadata.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Must be in a description context
      if (!/description/i.test(line)) return false;
      // Check for injection patterns in the description value
      const injectionPatterns = [
        /ignore\s+(previous|prior|above|all)/i,
        /forget\s+(previous|prior|your|all)/i,
        /\bsystem\s*:/i,
        /<\s*SYSTEM\s*>/i,
        /you\s+(are|must|should|will)\b/i,
        /do\s+not\s+(reveal|share|tell|mention)/i,
        /\[INST\]/i,
        /<<\s*SYS\s*>>/i,
        /IMPORTANT\s*:/i,
        /override/i,
      ];
      return injectionPatterns.some(p => p.test(line));
    },
    guards: [/sanitize/i, /escape/i, /filter/i, /validate/i],
  },
  {
    id: 'L3-008',
    title: 'npm lifecycle script (supply chain risk)',
    layer: 'L3',
    severity: 'medium',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'npm preinstall/postinstall scripts execute automatically during npm install. Malicious packages use these hooks to run arbitrary code on the developer machine.',
    recommendation: 'Audit all preinstall/postinstall scripts. Use --ignore-scripts for untrusted packages. Consider using npm config set ignore-scripts true globally.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      return /["'](preinstall|postinstall|preuninstall|postuninstall)["']\s*:/.test(line);
    },
    guards: [/husky/i, /lint-staged/i, /prepare/i],
  },
  {
    id: 'L3-009',
    title: 'Unpinned git dependency (rug-pull risk)',
    layer: 'L3',
    severity: 'high',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Dependencies pointing to git URLs without a pinned commit hash can be changed by the repo owner at any time (rug-pull). The next npm install may pull malicious code.',
    recommendation: 'Pin git dependencies to a specific commit hash: "package": "git+https://github.com/org/repo.git#abc123". Prefer npm registry packages with lockfile pinning.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // git+https:// or git+ssh:// or github: without a commit hash (#sha)
      if (/["']git\+(https|ssh):\/\//.test(line) && !/#[0-9a-f]{7,40}/.test(line)) return true;
      if (/["']github:/.test(line) && !/#[0-9a-f]{7,40}/.test(line)) return true;
      return false;
    },
    guards: [/#[0-9a-f]{7,40}/, /integrity/i, /commit/i],
  },
  {
    id: 'L3-010',
    title: 'User-provided text returned in tool response without PII redaction',
    layer: 'L3',
    severity: 'high',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(e) — Secure development',
    dora: 'Art. 6(8) — Data integrity and confidentiality',
    gdpr: 'Art. 5(1)(c) — Data minimisation; Art. 5(1)(b) — Purpose limitation',
    description: 'Tool responses that echo back or include user-provided text (e.g., body, message, content, query, input) may leak PII to downstream consumers, logs, or LLM context windows. GDPR Art. 5(1)(c) requires that only necessary personal data is processed.',
    recommendation: 'Apply PII redaction before including user-provided text in tool responses. Use a PII scanning/redaction step (pii.redact, presidio, or regex-based masking) on any user-sourced content before returning it.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Detect content/text fields in tool responses that reference user-input variables
      const isToolResponse = /\b(content|text)\s*[:=]/.test(line) && /\b(body|message|input|query|userText|user_text|userData|user_data|user_input|rawText|raw_text|originalText|original_text)\b/.test(line);
      return isToolResponse;
    },
    guards: [/redact/i, /mask/i, /sanitize/i, /pii/i, /anonymi[sz]e/i, /scrub/i, /clean/i, /strip.*pii/i],
    // Only flag if near a return/response context
    contextCheck: (lines, idx) => {
      const start = Math.max(0, idx - 5);
      const end = Math.min(lines.length - 1, idx + 5);
      for (let i = start; i <= end; i++) {
        if (/\breturn\b|\bresponse\b|\bcallTool\b|\bhandle\b|\btool\b/i.test(lines[i])) return true;
      }
      return false;
    },
  },
];

// Negative check rules for L3
const L3_NEGATIVE_RULES = [
  {
    id: 'L3-002',
    title: 'No input validation library detected',
    layer: 'L3',
    severity: 'medium',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'No input validation framework (zod, joi, yup, ajv, pydantic) was found. Tool inputs should be validated against a schema.',
    recommendation: 'Add input validation using zod, joi, yup, ajv (Node.js) or pydantic BaseModel/Field (Python), or use inputSchema with required fields in MCP tool definitions.',
    pattern: /\b(zod|joi|yup|ajv|schema.*validate|inputSchema.*required|validateInput|Joi\.object|z\.object|z\.string|z\.number|pydantic|BaseModel|Field\s*\(|Annotated\s*\[|marshmallow)\b/i,
  },
];

// ─────────────────────────────────────────────
// Security Rules — L4: MONITORING
// ─────────────────────────────────────────────

const L4_RULES = [
  {
    id: 'L4-002',
    title: 'console.log used as primary logging',
    layer: 'L4',
    severity: 'low',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    nis2: 'Art. 21(2)(g) — Audit and monitoring',
    description: 'console.log provides no log levels, rotation, or structured output. Use a proper logging framework in production.',
    recommendation: 'Use a structured logging library (winston, pino, bunyan) with log levels and optional file output.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      return /console\.(log|error|warn|info)\s*\(/.test(line);
    },
    guards: [],
    // This is a count-based rule - we count occurrences and only report if > 5
    countThreshold: 5,
  },
  {
    id: 'L4-003',
    title: 'Error details leaked to client',
    layer: 'L4',
    severity: 'medium',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.',
    recommendation: 'Return generic error messages to clients. Log detailed errors server-side only.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*#/.test(line)) return false;
      // stack/stackTrace/e.message in a return/content/response context
      if (/\b(stack|stackTrace|e\.message|err\.message|error\.message)\b/.test(line)) {
        if (/\b(content|text|return|response|send|json)\b/.test(line)) return true;
      }
      return false;
    },
    guards: [/production/i, /NODE_ENV/, /sanitizeError/i],
  },
  {
    id: 'L4-004',
    title: 'Silent error swallowing',
    layer: 'L4',
    severity: 'medium',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    nis2: 'Art. 21(2)(g) — Audit and monitoring',
    description: 'Empty catch blocks silently swallow errors, hiding security-relevant failures from operators.',
    recommendation: 'Always log caught errors, even if you handle them gracefully. At minimum, log at warning level.',
    // This is checked via multi-line context, not single-line
    test: null,
    multiLineTest: (lines, idx) => {
      const line = lines[idx];
      if (!/\bcatch\b/.test(line)) return false;
      // Look at next 1-3 lines for empty body
      const nextLines = lines.slice(idx + 1, idx + 4).join(' ').trim();
      if (/^\s*\}\s*$/.test(nextLines) || /^\s*$/.test(nextLines)) return true;
      // Catch with only console.log
      if (/^\s*console\.(log|error)\s*\(/.test(nextLines) && /\}\s*$/.test(nextLines)) return true;
      return false;
    },
    guards: [],
  },
];

// Negative check rules for L4
const L4_NEGATIVE_RULES = [
  {
    id: 'L4-001',
    title: 'No audit / telemetry in codebase',
    layer: 'L4',
    severity: 'medium',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    nis2: 'Art. 21(2)(g) — Audit and monitoring',
    description: 'No audit logging or telemetry was detected. MCP tool invocations should be logged for security monitoring and incident response.',
    recommendation: 'Implement audit logging for all tool invocations. Log: who called what tool, when, with which arguments, and the outcome.',
    pattern: /\b(audit|telemetry|log.*tool|log.*action|monitor|trace.*call|opentelemetry|AuditTrail|auditLog|structlog|loguru|logging\.getLogger)\b/i,
  },
  {
    id: 'L4-005',
    title: 'No rate limiting detected',
    layer: 'L4',
    severity: 'low',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'No rate limiting mechanism was found. MCP servers exposed over HTTP should limit request rates to prevent abuse.',
    recommendation: 'Implement rate limiting using a middleware (express-rate-limit, slowapi) or at the gateway/proxy level.',
    pattern: /\b(rateLimit|throttle|rateLimiter|slowapi|express.rate.limit|rate.limit)\b/i,
  },
];

const L4_RULES_EXTRA = [
  {
    id: 'L4-006',
    title: 'ReDoS pattern (regex denial of service)',
    layer: 'L4',
    severity: 'medium',
    owasp: 'A04:2021 Insecure Design',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'Regular expressions with nested quantifiers (e.g., (a+)+, (a*)*) are vulnerable to catastrophic backtracking. Malicious input can cause the regex engine to hang, enabling denial-of-service.',
    recommendation: 'Rewrite the regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers where supported. Consider using re2 or a regex engine with linear-time guarantees.',
    test: (line) => {
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*#/.test(line)) return false;
      // Detect nested quantifiers: (x+)+, (x*)+, (x+)*, (x*)*
      if (/\([^)]*[+*][^)]*\)[+*{]/.test(line)) return true;
      // Overlapping alternation with quantifiers: (a|a)+
      if (/\([^)]*\|[^)]*\)[+*{]/.test(line) && /(\w)\|.*\1/.test(line)) return true;
      return false;
    },
    guards: [/re2/i, /timeout/i, /safe.regex/i, /linear/i],
  },
];

// ─────────────────────────────────────────────
// L0: DISCOVERY
// ─────────────────────────────────────────────

function runL0Discovery(repoPath, allContent, sourceFiles) {
  const discovery = {
    totalSourceFiles: sourceFiles.length,
    transports: [],
    toolCount: 0,
    hasDependencyPinning: false,
    hasContainerization: false,
    dependencies: [],
    dependencyFile: null,
  };

  // Detect transports
  const transportPatterns = [
    { name: 'stdio', pattern: /\b(stdio|StdioServerTransport|stdio_server|NewStdioServer|server\.ServeStdio)\b/ },
    { name: 'SSE', pattern: /\b(SSEServerTransport|SseServerTransport|sse|NewSSEServer|SSEHandler)\b/i },
    { name: 'Streamable HTTP', pattern: /\b(StreamableHTTPServerTransport|httpStream|streamable.http|StreamableHTTP)\b/ },
  ];
  for (const tp of transportPatterns) {
    if (tp.pattern.test(allContent)) {
      discovery.transports.push(tp.name);
    }
  }

  // Count MCP tools
  const toolPatterns = [
    /name\s*:\s*['"`]/g,
    /tools\/list/g,
    /registerTool/g,
    /\.tool\s*\(/g,
    /\.action\s*\(/g,
    /\.query\s*\(/g,
    /\.mutation\s*\(/g,
    /@\w+\.tool\s*\(/g,                // Python FastMCP decorator
    /@server\.call_tool\s*\(/g,         // Python low-level MCP
    /@server\.list_tools\s*\(/g,        // Python low-level MCP
    /AddTool\s*\(/g,                    // Go mcp-go
    /NewTool\s*\(/g,                    // Go mcp-go
    /server\.HandleFunc\s*\(/g,         // Go MCP handler
  ];
  let maxToolCount = 0;
  for (const tp of toolPatterns) {
    const matches = allContent.match(tp);
    if (matches && matches.length > maxToolCount) {
      maxToolCount = matches.length;
    }
  }
  discovery.toolCount = maxToolCount;

  // Dependency pinning
  const lockFiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'poetry.lock', 'go.sum'];
  for (const lf of lockFiles) {
    if (fs.existsSync(path.join(repoPath, lf))) {
      discovery.hasDependencyPinning = true;
      break;
    }
  }

  // Containerization
  const containerFiles = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
  for (const cf of containerFiles) {
    if (fs.existsSync(path.join(repoPath, cf))) {
      discovery.hasContainerization = true;
      break;
    }
  }

  // List dependencies
  const pkgJsonPath = path.join(repoPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      discovery.dependencies = Object.entries(deps).map(([name, ver]) => `${name}@${ver}`);
      discovery.dependencyFile = 'package.json';
    } catch { /* skip */ }
  }

  const reqTxtPath = path.join(repoPath, 'requirements.txt');
  if (fs.existsSync(reqTxtPath)) {
    try {
      const content = fs.readFileSync(reqTxtPath, 'utf-8');
      discovery.dependencies = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      discovery.dependencyFile = 'requirements.txt';
    } catch { /* skip */ }
  }

  // Python pyproject.toml dependencies
  const pyprojectPath = path.join(repoPath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath) && !discovery.dependencyFile) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const deps = [];
      // Simple extraction of dependencies from pyproject.toml
      const depMatches = content.match(/["']([a-zA-Z0-9_-]+(?:\[[\w,]+\])?(?:[><=!~]+[^"']+)?)["']/g);
      if (depMatches) {
        for (const m of depMatches) {
          const cleaned = m.replace(/["']/g, '');
          if (cleaned.length > 1 && !/^(python|readme|license|description|name|version|author|url|homepage|repository)$/i.test(cleaned)) {
            deps.push(cleaned);
          }
        }
      }
      if (deps.length > 0) {
        discovery.dependencies = deps;
        discovery.dependencyFile = 'pyproject.toml';
      }
    } catch { /* skip */ }
  }

  // Python lock files for dependency pinning
  const pyLockFiles = ['poetry.lock', 'uv.lock', 'Pipfile.lock'];
  for (const lf of pyLockFiles) {
    if (fs.existsSync(path.join(repoPath, lf))) {
      discovery.hasDependencyPinning = true;
      break;
    }
  }

  // Go go.mod dependencies
  const goModPath = path.join(repoPath, 'go.mod');
  if (fs.existsSync(goModPath) && !discovery.dependencyFile) {
    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      const deps = [];
      const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
      if (requireBlock) {
        for (const line of requireBlock[1].split('\n')) {
          const m = line.trim().match(/^(\S+)\s+(\S+)/);
          if (m && !m[1].startsWith('//')) deps.push(`${m[1]}@${m[2]}`);
        }
      }
      // Single-line require (not followed by opening paren)
      for (const m of content.matchAll(/require\s+(\S+)\s+(v\S+)/g)) {
        if (!deps.some(d => d.startsWith(m[1]))) deps.push(`${m[1]}@${m[2]}`);
      }
      if (deps.length > 0) {
        discovery.dependencies = deps;
        discovery.dependencyFile = 'go.mod';
      }
    } catch { /* skip */ }
  }

  return discovery;
}

// ─────────────────────────────────────────────
// Main Scan Engine
// ─────────────────────────────────────────────

function scanFile(filePath, repoPath, allRules) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const lines = content.split('\n');
  const relPath = path.relative(repoPath, filePath);
  const findings = [];

  for (const rule of allRules) {
    if (rule.countThreshold) {
      // Count-based rule: count all matches, report once if over threshold
      let count = 0;
      for (let i = 0; i < lines.length; i++) {
        if (rule.test && rule.test(lines[i])) count++;
      }
      if (count > rule.countThreshold) {
        findings.push({
          id: rule.id,
          title: rule.title,
          layer: rule.layer,
          severity: rule.severity,
          owasp: rule.owasp,
          nis2: rule.nis2,
          gdpr: rule.gdpr || null,
          dora: rule.dora || null,
          file: relPath,
          line: null,
          code: `${count} occurrences found`,
          mitigated: false,
          guardLine: null,
          guardCode: null,
          description: rule.description,
          recommendation: rule.recommendation,
        });
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

      // Context check (for rules that need nearby context to confirm)
      if (rule.contextCheck && !rule.contextCheck(lines, i)) continue;

      // Guard check
      let severity = rule.severity;
      let guard = { mitigated: false, guardLine: null, guardCode: null };

      if (rule.guards && rule.guards.length > 0) {
        guard = checkGuard(lines, i, rule.guards);
        if (guard.mitigated) {
          severity = downgradeSeverity(severity);
        }
      }

      findings.push({
        id: rule.id,
        title: rule.title,
        layer: rule.layer,
        severity: severity,
        owasp: rule.owasp,
        nis2: rule.nis2,
        gdpr: rule.gdpr || null,
        dora: rule.dora || null,
        file: relPath,
        line: i + 1,
        code: lines[i].trim().substring(0, 120),
        mitigated: guard.mitigated,
        guardLine: guard.guardLine,
        guardCode: guard.guardCode,
        description: rule.description,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}

function runNegativeChecks(allContent, negativeRules) {
  const findings = [];

  for (const rule of negativeRules) {
    if (!rule.pattern.test(allContent)) {
      findings.push({
        id: rule.id,
        title: rule.title,
        layer: rule.layer,
        severity: rule.severity,
        owasp: rule.owasp,
        nis2: rule.nis2,
        gdpr: rule.gdpr || null,
        dora: rule.dora || null,
        file: '(entire codebase)',
        line: null,
        code: 'Pattern not found in any source file',
        mitigated: false,
        guardLine: null,
        guardCode: null,
        description: rule.description,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}

// ─────────────────────────────────────────────
// Report: Markdown
// ─────────────────────────────────────────────

function generateMarkdownReport(repoPath, findings, discovery, durationMs) {
  const repoName = path.basename(path.resolve(repoPath));
  const date = new Date().toISOString().split('T')[0];
  const filesScanned = discovery.totalSourceFiles;

  // Summary counts
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }

  // Layer counts
  const layers = {};
  for (const f of findings) {
    layers[f.layer] = (layers[f.layer] || 0) + 1;
  }

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

  let md = '';

  // Header
  md += `# MCP Security Scan Report\n\n`;
  md += `| Field | Value |\n|-------|-------|\n`;
  md += `| **Repository** | \`${repoName}\` |\n`;
  md += `| **Date** | ${date} |\n`;
  md += `| **Files Scanned** | ${filesScanned} |\n`;
  md += `| **Scan Duration** | ${(durationMs / 1000).toFixed(2)}s |\n`;
  md += `| **Scanner** | compuute-scan v${VERSION} |\n\n`;

  // Executive Summary
  md += `## Executive Summary\n\n`;
  md += `| Severity | Count |\n|----------|-------|\n`;
  md += `| \uD83D\uDD34 Critical | ${summary.critical} |\n`;
  md += `| \uD83D\uDFE0 High | ${summary.high} |\n`;
  md += `| \uD83D\uDFE1 Medium | ${summary.medium} |\n`;
  md += `| \uD83D\uDFE2 Low | ${summary.low} |\n`;
  md += `| Total | ${findings.length} |\n\n`;

  // Layer Assessment
  md += `## Layer Assessment\n\n`;
  md += `| Layer | Status | Findings | Description |\n|-------|--------|----------|-------------|\n`;
  for (const l of ['L0', 'L1', 'L2', 'L3', 'L4']) {
    const count = layers[l] || 0;
    md += `| ${l} | ${layerEmoji(count)} | ${count} | ${layerDescriptions[l]} |\n`;
  }
  md += '\n';

  // Detailed Findings (grouped by severity)
  md += `## Detailed Findings\n\n`;

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const severityLabels = {
    critical: '\uD83D\uDD34 CRITICAL',
    high: '\uD83D\uDFE0 HIGH',
    medium: '\uD83D\uDFE1 MEDIUM',
    low: '\uD83D\uDFE2 LOW',
    info: '\u2139\uFE0F INFO',
  };

  for (const sev of severityOrder) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    md += `### ${severityLabels[sev]}\n\n`;

    for (const f of sevFindings) {
      md += `#### ${f.id}: ${f.title}\n\n`;
      md += `| Field | Value |\n|-------|-------|\n`;
      md += `| **Severity** | ${sev.toUpperCase()}${f.mitigated ? ' (Mitigated)' : ''} |\n`;
      md += `| **Layer** | ${f.layer} |\n`;
      md += `| **OWASP** | ${f.owasp} |\n`;
      md += `| **NIS2** | ${f.nis2} |\n`;
      if (f.gdpr) md += `| **GDPR** | ${f.gdpr} |\n`;
      if (f.dora) md += `| **DORA** | ${f.dora} |\n`;
      if (f.file) md += `| **File** | \`${f.file}\` |\n`;
      if (f.line) md += `| **Line** | ${f.line} |\n`;
      md += '\n';

      if (f.code) {
        md += `**Code:**\n\`\`\`\n${f.code}\n\`\`\`\n\n`;
      }

      if (f.mitigated) {
        md += `> \u2705 **Mitigated** — Guard detected at line ${f.guardLine}: \`${f.guardCode}\`\n\n`;
      }

      md += `**Description:** ${f.description}\n\n`;
      md += `**Recommendation:** ${f.recommendation}\n\n`;
      md += `---\n\n`;
    }
  }

  // L0 Discovery
  md += `## L0: Discovery\n\n`;
  md += `| Property | Value |\n|----------|-------|\n`;
  md += `| **Transport** | ${discovery.transports.length ? discovery.transports.join(', ') : 'Not detected'} |\n`;
  md += `| **MCP Tools** | ~${discovery.toolCount} detected |\n`;
  md += `| **Dependency Pinning** | ${discovery.hasDependencyPinning ? '\u2705 Yes' : '\u274C No'} |\n`;
  md += `| **Containerization** | ${discovery.hasContainerization ? '\u2705 Yes' : '\u274C No'} |\n`;
  if (discovery.dependencies.length > 0) {
    md += `| **Dependencies** | ${discovery.dependencies.length} (${discovery.dependencyFile}) |\n`;
  }
  md += '\n';

  if (discovery.dependencies.length > 0) {
    md += `<details>\n<summary>Dependency List</summary>\n\n`;
    for (const dep of discovery.dependencies) {
      md += `- ${dep}\n`;
    }
    md += `\n</details>\n\n`;
  }

  // Footer
  md += `---\n\n`;
  md += `> This scan automates pattern detection. Professional judgment and manual review are required for a complete NIS2/DORA assessment. Contact: daniel@compuute.se\n\n`;
  md += `*Generated by compuute-scan v${VERSION} | Compuute AB*\n`;

  return md;
}

// ─────────────────────────────────────────────
// Report: JSON
// ─────────────────────────────────────────────

function generateJsonReport(repoPath, findings, discovery, durationMs) {
  const repoName = path.basename(path.resolve(repoPath));

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }

  const layers = {};
  for (const f of findings) {
    layers[f.layer] = (layers[f.layer] || 0) + 1;
  }

  return JSON.stringify({
    scanner: 'compuute-scan',
    version: VERSION,
    repo: repoName,
    date: new Date().toISOString(),
    filesScanned: discovery.totalSourceFiles,
    scanDurationMs: durationMs,
    summary,
    layers,
    l0Discovery: discovery,
    findings,
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

  // Walk files
  const sourceFiles = walkDir(repoPath);
  if (opts.verbose) {
    console.error(`Scanning ${sourceFiles.length} files in ${repoPath}...`);
  }

  // Build combined content for negative checks
  let allContent = '';
  const fileContents = {};
  for (const f of sourceFiles) {
    const content = readFileSafe(f);
    if (content) {
      fileContents[f] = content;
      allContent += content + '\n';
      if (opts.verbose) {
        console.error(`  ${path.relative(repoPath, f)}`);
      }
    }
  }

  // Collect all per-file rules
  const allFileRules = [...L1_RULES, ...L2_RULES, ...L3_RULES, ...L4_RULES, ...L4_RULES_EXTRA];

  // Run per-file scans
  let findings = [];
  for (const f of sourceFiles) {
    const fileFindings = scanFile(f, repoPath, allFileRules);
    findings.push(...fileFindings);
  }

  // Run negative checks
  const negativeRules = [...L1_NEGATIVE_RULES, ...L2_NEGATIVE_RULES, ...L3_NEGATIVE_RULES, ...L4_NEGATIVE_RULES];
  findings.push(...runNegativeChecks(allContent, negativeRules));

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
