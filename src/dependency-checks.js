// ─────────────────────────────────────────────
// Dependency Checks: CVE, Age, License
// ─────────────────────────────────────────────

// Offline CVE database — curated list of known-vulnerable package versions.
// Covers top npm/PyPI/Go packages with critical/high CVEs.
// Format: { package: [{ version: semver-range, cve: id, severity: level, title: desc }] }
const KNOWN_CVES = {
  // npm
  'lodash': [
    { below: '4.17.21', cve: 'CVE-2021-23337', severity: 'critical', title: 'Command injection via template' },
    { below: '4.17.19', cve: 'CVE-2020-8203', severity: 'high', title: 'Prototype pollution' },
  ],
  'axios': [
    { below: '1.7.4', cve: 'CVE-2024-39338', severity: 'high', title: 'SSRF via unexpected absolute URL' },
    { below: '1.6.0', cve: 'CVE-2023-45857', severity: 'medium', title: 'CSRF token exposure' },
  ],
  'express': [
    { below: '4.20.0', cve: 'CVE-2024-43796', severity: 'medium', title: 'XSS via response.redirect' },
    { below: '4.19.2', cve: 'CVE-2024-29041', severity: 'medium', title: 'Open redirect' },
  ],
  'jsonwebtoken': [
    { below: '9.0.0', cve: 'CVE-2022-23529', severity: 'critical', title: 'Arbitrary code execution via secret object' },
  ],
  'node-fetch': [
    { below: '2.6.7', cve: 'CVE-2022-0235', severity: 'high', title: 'Cookie leak to third-party' },
  ],
  'minimatch': [
    { below: '3.0.5', cve: 'CVE-2022-3517', severity: 'high', title: 'ReDoS via brace expansion' },
  ],
  'semver': [
    { below: '7.5.2', cve: 'CVE-2022-25883', severity: 'medium', title: 'ReDoS via long version string' },
  ],
  'tar': [
    { below: '6.1.9', cve: 'CVE-2021-37712', severity: 'high', title: 'Arbitrary file creation via symlink' },
  ],
  'shell-quote': [
    { below: '1.7.3', cve: 'CVE-2021-42740', severity: 'critical', title: 'Command injection' },
  ],
  'got': [
    { below: '11.8.5', cve: 'CVE-2022-33987', severity: 'medium', title: 'Open redirect' },
  ],
  'qs': [
    { below: '6.10.3', cve: 'CVE-2022-24999', severity: 'high', title: 'Prototype pollution' },
  ],
  'moment': [
    { below: '2.29.4', cve: 'CVE-2022-31129', severity: 'high', title: 'ReDoS via date string' },
  ],
  'xml2js': [
    { below: '0.5.0', cve: 'CVE-2023-0842', severity: 'medium', title: 'Prototype pollution' },
  ],
  'tough-cookie': [
    { below: '4.1.3', cve: 'CVE-2023-26136', severity: 'medium', title: 'Prototype pollution' },
  ],
  'yaml': [
    { below: '2.2.2', cve: 'CVE-2023-2251', severity: 'high', title: 'ReDoS via crafted YAML' },
  ],
  'fast-xml-parser': [
    { below: '4.2.5', cve: 'CVE-2023-34104', severity: 'high', title: 'Prototype pollution' },
  ],
  'jose': [
    { below: '4.11.4', cve: 'CVE-2024-28176', severity: 'medium', title: 'Denial of service via JWE' },
  ],
  'undici': [
    { below: '5.28.4', cve: 'CVE-2024-30260', severity: 'medium', title: 'Cookie leak via HTTP redirect' },
  ],
  'path-to-regexp': [
    { below: '0.1.10', cve: 'CVE-2024-45296', severity: 'high', title: 'ReDoS via backtracking' },
  ],
  'body-parser': [
    { below: '1.20.3', cve: 'CVE-2024-45590', severity: 'high', title: 'Denial of service' },
  ],

  // PyPI
  'requests': [
    { below: '2.32.0', cve: 'CVE-2024-35195', severity: 'medium', title: 'Certificate verification bypass' },
  ],
  'django': [
    { below: '4.2.16', cve: 'CVE-2024-45231', severity: 'medium', title: 'Information disclosure' },
  ],
  'flask': [
    { below: '2.3.2', cve: 'CVE-2023-30861', severity: 'high', title: 'Session cookie leak' },
  ],
  'werkzeug': [
    { below: '3.0.3', cve: 'CVE-2024-34069', severity: 'high', title: 'Remote code execution via debugger' },
  ],
  'jinja2': [
    { below: '3.1.4', cve: 'CVE-2024-34064', severity: 'medium', title: 'XSS via xmlattr filter' },
  ],
  'cryptography': [
    { below: '42.0.4', cve: 'CVE-2024-26130', severity: 'high', title: 'NULL pointer dereference in PKCS12' },
  ],
  'urllib3': [
    { below: '2.0.7', cve: 'CVE-2023-45803', severity: 'medium', title: 'Cookie leak on redirect' },
  ],
  'pydantic': [
    { below: '1.10.13', cve: 'CVE-2024-3772', severity: 'medium', title: 'ReDoS via email validation' },
  ],
  'pillow': [
    { below: '10.3.0', cve: 'CVE-2024-28219', severity: 'high', title: 'Buffer overflow in TIFF' },
  ],
  'aiohttp': [
    { below: '3.9.4', cve: 'CVE-2024-30251', severity: 'high', title: 'Denial of service' },
  ],
  'fastapi': [
    { below: '0.109.1', cve: 'CVE-2024-24762', severity: 'medium', title: 'DoS via multipart form' },
  ],
  'starlette': [
    { below: '0.36.2', cve: 'CVE-2024-24762', severity: 'medium', title: 'DoS via multipart form' },
  ],
  'sqlalchemy': [
    { below: '2.0.0b1', cve: 'CVE-2023-1370', severity: 'medium', title: 'SQL injection via text clause' },
  ],
  'paramiko': [
    { below: '3.4.0', cve: 'CVE-2023-48795', severity: 'medium', title: 'Terrapin SSH prefix truncation' },
  ],
  'certifi': [
    { below: '2023.7.22', cve: 'CVE-2023-37920', severity: 'high', title: 'Removed e-Tugra root certificate' },
  ],

  // Go modules
  'golang.org/x/crypto': [
    { below: 'v0.17.0', cve: 'CVE-2023-48795', severity: 'medium', title: 'Terrapin SSH prefix truncation' },
  ],
  'golang.org/x/net': [
    { below: 'v0.23.0', cve: 'CVE-2023-45288', severity: 'high', title: 'HTTP/2 CONTINUATION flood' },
  ],
  'golang.org/x/text': [
    { below: 'v0.3.8', cve: 'CVE-2022-32149', severity: 'high', title: 'Denial of service via language tag' },
  ],
  'github.com/gin-gonic/gin': [
    { below: 'v1.9.1', cve: 'CVE-2023-29401', severity: 'medium', title: 'Unsafe HTML in context.Header' },
  ],
  'github.com/go-git/go-git/v5': [
    { below: 'v5.11.0', cve: 'CVE-2023-49568', severity: 'critical', title: 'DoS via malicious Git object' },
  ],
  'google.golang.org/grpc': [
    { below: 'v1.56.3', cve: 'CVE-2023-44487', severity: 'high', title: 'HTTP/2 rapid reset DoS' },
  ],
  'google.golang.org/protobuf': [
    { below: 'v1.33.0', cve: 'CVE-2024-24786', severity: 'medium', title: 'Infinite loop on JSON unmarshal' },
  ],
};

// Known copyleft / restrictive licenses that may be problematic in commercial projects
const COPYLEFT_LICENSES = new Set([
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'SSPL-1.0', 'EUPL-1.2', 'OSL-3.0', 'CPAL-1.0',
  'CC-BY-SA-4.0', 'CC-BY-NC-4.0',
]);

/**
 * Parse a version string into comparable parts.
 * Handles: "1.2.3", "^1.2.3", "~1.2.3", ">=1.2.3", "v1.2.3"
 * Returns null if unparseable.
 */
function parseVersion(verStr) {
  if (!verStr) return null;
  // Strip prefix chars: ^~>=<v
  const cleaned = verStr.replace(/^[\^~>=<v]+/, '').trim();
  // Handle calver or dates like "2023.7.22"
  const parts = cleaned.split('.').map(p => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });
  if (parts.length === 0) return null;
  // Pad to at least 3 parts
  while (parts.length < 3) parts.push(0);
  return parts;
}

/**
 * Returns true if actualVer < thresholdVer.
 */
function isVersionBelow(actualVer, thresholdVer) {
  const actual = parseVersion(actualVer);
  const threshold = parseVersion(thresholdVer);
  if (!actual || !threshold) return false;

  const len = Math.max(actual.length, threshold.length);
  for (let i = 0; i < len; i++) {
    const a = actual[i] || 0;
    const t = threshold[i] || 0;
    if (a < t) return true;
    if (a > t) return false;
  }
  return false; // equal
}

/**
 * Extract package name and version from dependency string.
 * Handles: "lodash@^4.17.15", "requests>=2.28.0", "golang.org/x/net@v0.10.0"
 */
function parseDependency(depStr) {
  if (!depStr) return null;

  // npm-style: name@version
  const atIdx = depStr.lastIndexOf('@');
  if (atIdx > 0) {
    return {
      name: depStr.substring(0, atIdx),
      version: depStr.substring(atIdx + 1),
    };
  }

  // Python-style: name>=version, name==version, name~=version
  const pyMatch = depStr.match(/^([a-zA-Z0-9_-]+)\s*([><=~!]+)\s*(.+)/);
  if (pyMatch) {
    return { name: pyMatch[1].toLowerCase(), version: pyMatch[3].trim() };
  }

  // Go-style with spaces: golang.org/x/net v0.10.0
  const goMatch = depStr.match(/^(\S+)\s+(v\S+)/);
  if (goMatch) {
    return { name: goMatch[1], version: goMatch[2] };
  }

  return null;
}

/**
 * Check dependencies against the offline CVE database.
 * Returns array of findings.
 */
function checkKnownCVEs(dependencies, dependencyFile) {
  const findings = [];
  if (!dependencies || dependencies.length === 0) return findings;

  for (const depStr of dependencies) {
    const dep = parseDependency(depStr);
    if (!dep) continue;

    // Look up the package in our database
    const cves = KNOWN_CVES[dep.name] || KNOWN_CVES[dep.name.toLowerCase()];
    if (!cves) continue;

    for (const cve of cves) {
      if (isVersionBelow(dep.version, cve.below)) {
        findings.push({
          id: 'L0-CVE',
          title: `Known vulnerability in ${dep.name}`,
          layer: 'L0',
          severity: cve.severity,
          owasp: 'A06:2021 Vulnerable and Outdated Components',
          nis2: 'Art. 21(2)(e) — Secure development',
          gdpr: null,
          dora: null,
          file: dependencyFile || '(dependency)',
          line: null,
          code: `${dep.name}@${dep.version} < ${cve.below}`,
          mitigated: false,
          guardLine: null,
          guardCode: null,
          description: `${cve.cve}: ${cve.title}. Installed version ${dep.version} is below the fix version ${cve.below}.`,
          recommendation: `Upgrade ${dep.name} to version ${cve.below} or later. Run: npm update ${dep.name} (npm) / pip install --upgrade ${dep.name} (pip) / go get ${dep.name}@latest (Go).`,
        });
      }
    }
  }

  return findings;
}

/**
 * Check for dependencies that appear outdated based on version heuristics.
 * Flags packages pinned to very old major versions.
 * Returns array of findings.
 */
function checkDependencyAge(dependencies, dependencyFile) {
  const findings = [];
  if (!dependencies || dependencies.length === 0) return findings;

  // Known packages with their current major versions (as of 2025)
  // If a project uses a version 2+ majors behind, flag it
  const MAJOR_VERSION_EXPECTATIONS = {
    // npm
    'express': 4, 'react': 18, 'react-dom': 18, 'next': 14,
    'typescript': 5, 'webpack': 5, 'eslint': 8, 'jest': 29,
    'axios': 1, 'lodash': 4, 'mongoose': 7, 'prisma': 5,
    '@prisma/client': 5, 'socket.io': 4, 'fastify': 4,
    'graphql': 16, 'pg': 8, 'mysql2': 3, 'redis': 4,
    'commander': 11, 'chalk': 5, 'dotenv': 16, 'zod': 3,
    'uuid': 9, 'sharp': 0, 'cors': 2,
    // PyPI
    'django': 5, 'flask': 3, 'fastapi': 0, 'sqlalchemy': 2,
    'requests': 2, 'numpy': 1, 'pandas': 2, 'pydantic': 2,
    'celery': 5, 'pillow': 10, 'boto3': 1, 'cryptography': 42,
    // Go (use 1 as baseline; Go modules mostly stay at v1/v2)
  };

  for (const depStr of dependencies) {
    const dep = parseDependency(depStr);
    if (!dep) continue;

    const expectedMajor = MAJOR_VERSION_EXPECTATIONS[dep.name];
    if (expectedMajor === undefined) continue;

    const version = parseVersion(dep.version);
    if (!version) continue;

    const actualMajor = version[0];
    const majorsBehind = expectedMajor - actualMajor;

    // Only flag if 2+ major versions behind (to avoid noise)
    if (majorsBehind >= 2) {
      findings.push({
        id: 'L0-AGE',
        title: `Outdated dependency: ${dep.name}`,
        layer: 'L0',
        severity: 'low',
        owasp: 'A06:2021 Vulnerable and Outdated Components',
        nis2: 'Art. 21(2)(e) — Secure development',
        gdpr: null,
        dora: null,
        file: dependencyFile || '(dependency)',
        line: null,
        code: `${dep.name}@${dep.version} (current major: ${expectedMajor})`,
        mitigated: false,
        guardLine: null,
        guardCode: null,
        description: `${dep.name} is ${majorsBehind} major version(s) behind (using v${actualMajor}, current is v${expectedMajor}). Outdated dependencies may lack security patches and bug fixes.`,
        recommendation: `Consider upgrading ${dep.name} to the latest major version. Review the changelog for breaking changes before upgrading.`,
      });
    }
  }

  return findings;
}

/**
 * Check for copyleft or restrictive licenses in dependencies.
 * Reads package.json license fields for npm projects.
 * Returns array of findings.
 */
function checkLicenseCompliance(repoPath, dependencies, dependencyFile) {
  const findings = [];
  if (!dependencies || dependencies.length === 0) return findings;

  // Only check npm projects with node_modules available
  if (dependencyFile !== 'package.json') return findings;

  const nodeModulesPath = path.join(repoPath, 'node_modules');
  if (!fs.existsSync(nodeModulesPath)) return findings;

  for (const depStr of dependencies) {
    const dep = parseDependency(depStr);
    if (!dep) continue;

    // Read the dependency's package.json
    const depPkgPath = path.join(nodeModulesPath, dep.name, 'package.json');
    if (!fs.existsSync(depPkgPath)) continue;

    try {
      const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));
      const license = depPkg.license || '';
      const licenseStr = typeof license === 'string' ? license : (license.type || '');

      if (COPYLEFT_LICENSES.has(licenseStr)) {
        findings.push({
          id: 'L0-LIC',
          title: `Copyleft license: ${dep.name}`,
          layer: 'L0',
          severity: 'medium',
          owasp: null,
          nis2: 'Art. 21(2)(e) — Secure development',
          gdpr: null,
          dora: null,
          file: dependencyFile,
          line: null,
          code: `${dep.name}: ${licenseStr}`,
          mitigated: false,
          guardLine: null,
          guardCode: null,
          description: `${dep.name} uses the ${licenseStr} license, which is a copyleft license. This may require you to release your source code under the same license if you distribute or deploy your software.`,
          recommendation: `Review the ${licenseStr} license obligations. Consider whether your usage is compatible (e.g., LGPL for dynamic linking). If not, find an alternative package with a permissive license (MIT, Apache-2.0, BSD).`,
        });
      }
    } catch {
      // Skip unreadable package.json
    }
  }

  return findings;
}

/**
 * Run all dependency checks.
 * Returns array of findings.
 */
function runDependencyChecks(repoPath, discovery) {
  const findings = [];

  // CVE matching
  findings.push(...checkKnownCVEs(discovery.dependencies, discovery.dependencyFile));

  // Dependency age
  findings.push(...checkDependencyAge(discovery.dependencies, discovery.dependencyFile));

  // License compliance
  findings.push(...checkLicenseCompliance(repoPath, discovery.dependencies, discovery.dependencyFile));

  return findings;
}


