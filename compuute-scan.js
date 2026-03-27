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

const VERSION = '0.1.0';
const MAX_FILE_SIZE = 500 * 1024; // 500 KB
const GUARD_WINDOW = 15; // lines above/below to check for guards

const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.py', '.mjs', '.cjs', '.tsx', '.jsx',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  'coverage', '.turbo', '.next', '.venv', 'venv',
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
    verbose: false,
    layer: null,    // filter by layer e.g. "L1"
    minSeverity: null,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--help' || a === '-h') { opts.help = true; }
    else if (a === '--json') { opts.json = true; }
    else if (a === '--verbose' || a === '-v') { opts.verbose = true; }
    else if (a === '--output' || a === '-o') { opts.output = args[++i]; }
    else if (a === '--layer') { opts.layer = args[++i]?.toUpperCase(); }
    else if (a === '--min-severity') { opts.minSeverity = args[++i]?.toLowerCase(); }
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
  --output <file>      Write report to file (markdown or json)
  --json               Output JSON instead of markdown
  --verbose            Show files being scanned
  --layer <L0-L4>      Filter findings by layer
  --min-severity <s>   Filter: critical, high, medium, low
  --help               Show this message

Examples:
  compuute-scan ./my-mcp-server
  compuute-scan ./server --output report.md
  compuute-scan ./server --json --output report.json
  compuute-scan ./server --layer L1 --min-severity high
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
      return /['"]0\.0\.0\.0['"]/.test(line) && /(listen|bind|host|run)\s*[=(]/.test(line) || /host\s*[:=]\s*['"]0\.0\.0\.0['"]/.test(line);
    },
    guards: [/reverse.?proxy/i, /nginx/i, /traefik/i, /behind.*proxy/i],
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
      return /path\.join\s*\(/.test(line) || /os\.path\.join\s*\(/.test(line);
    },
    guards: [
      /startsWith/, /realpath/, /resolve/, /includes\s*\(\s*['"]\.\.['"]/,
      /throw/, /reject/, /Error/, /normalize/, /is_relative_to/,
      /commonpath/, /abspath/,
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
        return /^[^.]*\bopen\s*\(/.test(line.trim());
      }
      return false;
    },
    guards: [
      /startsWith/, /realpath/, /resolve/, /includes\s*\(\s*['"]\.\.['"]/,
      /throw/, /reject/, /Error/, /whitelist/i, /allowlist/i, /allowedPaths/i,
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
        if (/process\.env|os\.environ|getenv/.test(line)) return false;
        return true;
      }
      return false;
    },
    guards: [/process\.env/, /os\.environ/, /getenv/, /vault/i, /secrets?\s*manager/i],
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
    pattern: /\b(auth|authenticate|requireAuth|jwt|oauth|bearer|api[-_]?key|apiKey|token.*verify|verifyToken|passport|session|login)\b/i,
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
    description: 'No input validation framework (zod, joi, yup, ajv) was found. Tool inputs should be validated against a schema.',
    recommendation: 'Add input validation using zod, joi, yup, ajv, or use inputSchema with required fields in MCP tool definitions.',
    pattern: /\b(zod|joi|yup|ajv|schema.*validate|inputSchema.*required|validateInput|Joi\.object|z\.object|z\.string|z\.number)\b/i,
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
    pattern: /\b(audit|telemetry|log.*tool|log.*action|monitor|trace.*call|opentelemetry|AuditTrail|auditLog)\b/i,
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
    { name: 'stdio', pattern: /\b(stdio|StdioServerTransport)\b/ },
    { name: 'SSE', pattern: /\b(SSEServerTransport|sse)\b/i },
    { name: 'Streamable HTTP', pattern: /\b(StreamableHTTPServerTransport|httpStream)\b/ },
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
  const lockFiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'poetry.lock'];
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
    process.exit(1);
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
  const allFileRules = [...L1_RULES, ...L2_RULES, ...L3_RULES, ...L4_RULES];

  // Run per-file scans
  let findings = [];
  for (const f of sourceFiles) {
    const fileFindings = scanFile(f, repoPath, allFileRules);
    findings.push(...fileFindings);
  }

  // Run negative checks
  const negativeRules = [...L2_NEGATIVE_RULES, ...L3_NEGATIVE_RULES, ...L4_NEGATIVE_RULES];
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
  if (opts.json) {
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

  // Exit with 0 always (tool ran successfully; findings are informational)
  process.exit(0);
}

main();
