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

  // ─── Rust Rules ───

  {
    id: 'L1-023',
    title: 'Rust unsafe block',
    layer: 'L1',
    severity: 'high',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'unsafe {} blocks bypass Rust memory safety guarantees. In MCP servers this can lead to buffer overflows, use-after-free, and other memory corruption vulnerabilities exploitable by untrusted input.',
    recommendation: 'Avoid unsafe blocks. Use safe abstractions from the standard library or well-audited crates. If unavoidable, add #[deny(unsafe_code)] at the crate level and document why each unsafe block is sound.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /\bunsafe\s*\{/.test(line);
    },
    guards: [/deny\(unsafe_code\)/, /SAFETY:/, /Safety:/, /# Safety/, /\bvalidate\b/i],
  },
  {
    id: 'L1-024',
    title: 'Rust Command::new with user input',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'std::process::Command::new() with format! or user-controlled strings enables command injection. Unlike Go, Rust Command bypasses the shell by default, but shell injection is still possible via /bin/sh -c.',
    recommendation: 'Pass arguments via .arg() instead of building command strings. Never use format! to construct command arguments. Validate input against an allowlist.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // Command::new with format! or variable (not literal)
      if (/Command::new\s*\(\s*format!/.test(line)) return true;
      if (/Command::new\s*\(\s*&?format!/.test(line)) return true;
      // Command::new("sh") or Command::new("bash")
      if (/Command::new\s*\(\s*"(sh|bash|cmd)"/.test(line)) return true;
      return false;
    },
    guards: [/\.arg\s*\(/, /allowlist/i, /whitelist/i, /validate/i],
  },
  {
    id: 'L1-025',
    title: 'Rust SQL query with format!',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Building SQL queries with format!() in Rust enables SQL injection when user input is interpolated directly into the query string.',
    recommendation: 'Use parameterized queries with sqlx::query!() or diesel query builder. Never use format! to build SQL strings with user input.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // .query(&format!("...")) or .execute(&format!("..."))
      if (/\.(query|execute|query_as|fetch_one|fetch_all)\s*\(\s*&?format!/.test(line)) return true;
      // sqlx::query(format!(...))
      if (/query\s*\(\s*&?format!\s*\(/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
      return false;
    },
    guards: [/sqlx::query!/, /query!\s*\(/, /diesel/, /prepared/i, /parameterized/i, /bind\s*\(/],
  },
  {
    id: 'L1-026',
    title: 'Rust TLS certificate verification disabled',
    layer: 'L1',
    severity: 'high',
    owasp: 'A02:2021 Cryptographic Failures',
    nis2: 'Art. 21(2)(h) — Cryptography and encryption',
    description: 'danger_accept_invalid_certs(true) disables TLS certificate validation in reqwest/rustls, enabling man-in-the-middle attacks.',
    recommendation: 'Remove danger_accept_invalid_certs(true). Use proper CA certificates. If self-signed certs are needed for development, restrict via compile-time feature flags.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /danger_accept_invalid_certs\s*\(\s*true\s*\)/.test(line);
    },
    guards: [/development/i, /testing/i, /cfg!\s*\(\s*debug_assertions/, /cfg!\s*\(\s*test/],
  },

  // ─── C#/.NET Rules ───

  {
    id: 'L1-028',
    title: 'C# Process.Start with user input',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Process.Start() executes external programs. If the arguments include user-controlled input, an attacker can execute arbitrary commands.',
    recommendation: 'Avoid passing user input to Process.Start(). Use an allowlist of permitted commands and validate arguments. Never use shell execution (UseShellExecute = true) with user input.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // Process.Start with variable (not just literal)
      if (/Process\.Start\s*\(/.test(line)) return true;
      // ProcessStartInfo with FileName from variable
      if (/FileName\s*=\s*[^"']/.test(line) && /ProcessStartInfo/.test(line)) return true;
      return false;
    },
    guards: [/allowlist/i, /whitelist/i, /UseShellExecute\s*=\s*false/, /ValidateCommand/i],
  },
  {
    id: 'L1-029',
    title: 'C# SQL string concatenation (SqlCommand)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Building SQL queries with string concatenation or interpolation in SqlCommand enables SQL injection.',
    recommendation: 'Use parameterized queries: new SqlCommand("SELECT * FROM t WHERE id = @id", conn) with cmd.Parameters.AddWithValue("@id", id).',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // new SqlCommand("..." + var) or SqlCommand($"...")
      if (/SqlCommand\s*\(\s*\$"/.test(line)) return true;
      if (/SqlCommand\s*\(\s*".*\+/.test(line)) return true;
      // CommandText = $"..." or "..." +
      if (/CommandText\s*=\s*\$"/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
      if (/CommandText\s*=\s*".*\+/.test(line) && /SELECT|INSERT|UPDATE|DELETE|WHERE/i.test(line)) return true;
      return false;
    },
    guards: [/Parameters\.Add/, /SqlParameter/, /parameterized/i, /@\w+/],
  },
  {
    id: 'L1-030',
    title: 'C# [AllowAnonymous] on sensitive endpoint',
    layer: 'L1',
    severity: 'high',
    owasp: 'A01:2021 Broken Access Control',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: '[AllowAnonymous] bypasses authentication on the decorated endpoint. If applied to sensitive endpoints, unauthenticated users can access protected resources.',
    recommendation: 'Review all [AllowAnonymous] usages. Only apply to truly public endpoints (login, health check). Prefer [Authorize] as the default and explicitly mark exceptions.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /\[AllowAnonymous\]/.test(line);
    },
    guards: [/\[Authorize\]/, /\[Authorize\(/, /RequireAuthorization/, /IsAuthenticated/],
  },
  {
    id: 'L1-031',
    title: 'C# deserialization of untrusted data',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'BinaryFormatter, SoapFormatter, and ObjectStateFormatter deserialize arbitrary .NET types and can execute code during deserialization. These are banned by Microsoft.',
    recommendation: 'Use System.Text.Json or JsonSerializer instead. Never use BinaryFormatter — it is obsolete and dangerous. If binary serialization is required, use MessagePack or protobuf.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /\b(BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer)\b/.test(line);
    },
    guards: [/System\.Text\.Json/, /JsonSerializer/, /JsonConvert/],
  },
  {
    id: 'L1-032',
    title: 'C# CORS AllowAnyOrigin',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: 'AllowAnyOrigin() in ASP.NET Core CORS policy allows any website to make cross-origin requests.',
    recommendation: 'Use WithOrigins("https://specific-domain.com") instead of AllowAnyOrigin(). Never combine AllowAnyOrigin with AllowCredentials.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /\.AllowAnyOrigin\s*\(/.test(line);
    },
    guards: [/\.WithOrigins\s*\(/, /AllowedOrigins/i],
  },

  // ─── Java/Kotlin Rules ───

  {
    id: 'L1-033',
    title: 'Java Runtime.exec() command execution',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Runtime.getRuntime().exec() executes system commands. If user input is concatenated into the command string, it enables command injection.',
    recommendation: 'Use ProcessBuilder with explicit argument lists instead. Never concatenate user input into command strings. Validate input against an allowlist.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // Runtime.getRuntime().exec(
      if (/Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/.test(line)) return true;
      // ProcessBuilder with string concat or shell
      if (/ProcessBuilder\s*\(/.test(line) && /\+/.test(line)) return true;
      // Kotlin: Runtime.getRuntime().exec
      if (/runtime\s*\(\s*\)\.exec\s*\(/i.test(line)) return true;
      return false;
    },
    guards: [/ProcessBuilder/, /allowlist/i, /whitelist/i, /validateCommand/i],
  },
  {
    id: 'L1-034',
    title: 'Java/Kotlin SQL string concatenation (JDBC)',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A03:2021 Injection',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'Building SQL queries with string concatenation in JDBC Statement enables SQL injection.',
    recommendation: 'Use PreparedStatement with parameterized queries: conn.prepareStatement("SELECT * FROM t WHERE id = ?") and ps.setString(1, id).',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // executeQuery("..." + var) or executeUpdate("..." + var)
      if (/\.(executeQuery|executeUpdate|execute)\s*\(\s*".*\+/.test(line)) return true;
      // Statement.execute with string concat
      if (/\.(executeQuery|executeUpdate|execute)\s*\(\s*[a-zA-Z]/.test(line) && !/PreparedStatement/.test(line)) return true;
      // Kotlin string template in SQL
      if (/\.(executeQuery|executeUpdate|execute)\s*\(\s*".*\$\{/.test(line)) return true;
      return false;
    },
    guards: [/PreparedStatement/, /prepareStatement/, /setString/, /setInt/, /NamedParameterJdbc/i, /JpaRepository/i],
  },
  {
    id: 'L1-035',
    title: 'Java ObjectInputStream deserialization',
    layer: 'L1',
    severity: 'critical',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'ObjectInputStream.readObject() deserializes arbitrary Java objects and can execute code via gadget chains. This is the root cause of most Java deserialization CVEs.',
    recommendation: 'Avoid Java native serialization. Use JSON (Jackson/Gson) or protobuf. If unavoidable, use an ObjectInputFilter (JEP 290) to restrict allowed classes.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // ObjectInputStream or readObject()
      if (/new\s+ObjectInputStream\s*\(/.test(line)) return true;
      if (/\.readObject\s*\(/.test(line) && !/JsonReader|XmlReader|DataReader/.test(line)) return true;
      return false;
    },
    guards: [/ObjectInputFilter/, /JEP.290/i, /ValidatingObjectInputStream/, /SerialKiller/i, /Jackson/, /Gson/],
  },
  {
    id: 'L1-036',
    title: 'Spring Security permitAll on sensitive path',
    layer: 'L1',
    severity: 'high',
    owasp: 'A01:2021 Broken Access Control',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'permitAll() in Spring Security configuration disables authentication for the matched endpoints. If applied too broadly, it exposes protected resources.',
    recommendation: 'Review all permitAll() usages. Apply only to public endpoints (login, health, static). Use authenticated() or hasRole() as the default.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      return /\.permitAll\s*\(/.test(line);
    },
    guards: [/\.authenticated\s*\(/, /\.hasRole\s*\(/, /\.hasAuthority\s*\(/, /\.denyAll\s*\(/],
  },
  {
    id: 'L1-037',
    title: 'Java/Kotlin CORS @CrossOrigin wildcard',
    layer: 'L1',
    severity: 'high',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(d) — Network security',
    description: '@CrossOrigin without explicit origins or with origins="*" allows any website to make cross-origin requests.',
    recommendation: 'Specify explicit allowed origins: @CrossOrigin(origins = "https://app.example.com"). Configure CORS centrally via WebMvcConfigurer.',
    test: (line) => {
      if (/^\s*\/\//.test(line)) return false;
      // @CrossOrigin without origins or with "*"
      if (/@CrossOrigin\s*$/.test(line.trim())) return true;
      if (/@CrossOrigin\s*\(\s*\)/.test(line)) return true;
      if (/@CrossOrigin\s*\(.*origins\s*=\s*"\*"/.test(line)) return true;
      return false;
    },
    guards: [/origins\s*=\s*"https?:/, /allowedOrigins.*https?:/i, /CorsConfiguration/],
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
  {
    id: 'L1-027',
    title: 'Rust crate missing #[deny(unsafe_code)]',
    layer: 'L1',
    severity: 'medium',
    owasp: 'A05:2021 Security Misconfiguration',
    nis2: 'Art. 21(2)(e) — Secure development',
    description: 'The crate does not have #[deny(unsafe_code)] or #![forbid(unsafe_code)] at the crate level. Without this, unsafe blocks can be added without triggering a compile error.',
    recommendation: 'Add #![forbid(unsafe_code)] or #![deny(unsafe_code)] at the top of lib.rs/main.rs to enforce memory safety at the crate level.',
    pattern: /#!\[(?:deny|forbid)\s*\(\s*unsafe_code\s*\)\]/,
    // Only fire for Rust projects (detected by Cargo.toml presence)
    contextRequired: 'rust',
  },
];

