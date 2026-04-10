#!/usr/bin/env node
// compuute-scan v0.3.0 — MCP Server Security Scanner
// Compuute AB | daniel@compuute.se
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
// L2-L4 rules available in Compuute Professional Audit
// https://compuute.se/audit
// ─────────────────────────────────────────────

const L2_RULES = [];
const L2_NEGATIVE_RULES = [];
const L3_RULES = [];
const L3_NEGATIVE_RULES = [];
const L4_RULES = [];
const L4_NEGATIVE_RULES = [];
const L4_RULES_EXTRA = [];

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
  for (const l of ['L0', 'L1']) {
    const count = layers[l] || 0;
    md += `| ${l} | ${layerEmoji(count)} | ${count} | ${layerDescriptions[l]} |\n`;
  }
  md += `| L2-L4 | — | — | [Available in Compuute Professional Audit](https://compuute.se/audit) |\n`;
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
  md += `## Full Security Assessment\n\n`;
  md += `This scan covers **L0 Discovery + L1 Sandboxing** (${findings.length} findings).\n\n`;
  md += `Production MCP deployments need deeper analysis:\n\n`;
  md += `- **L2 Authorization** — RBAC, secret management, JWT/OAuth, PII/GDPR compliance\n`;
  md += `- **L3 Tool Integrity** — SSRF, injection, prompt poisoning, supply chain\n`;
  md += `- **L4 Runtime Monitoring** — audit logging, rate limiting, error leakage\n\n`;
  md += `**49 rules. OWASP LLM Top 10 (10/10). NIS2 Art. 21 (7/7). DORA. GDPR (6/6).**\n\n`;
  md += `> [Book a Compuute Security Assessment](https://compuute.se/audit)\n\n`;
  md += `*Generated by compuute-scan v${VERSION} (open source) | Compuute AB*\n`;

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
      message: 'This scan covers L0-L1. Full L2-L4 assessment available with Compuute Professional Audit.',
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

  // Upgrade notice (stderr so it doesn't pollute report output)
  if (!opts.json && !opts.sarif) {
    console.error('');
    console.error('L0-L1 scan complete. For full L2-L4 assessment + compliance mapping:');
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
