import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import {
  calculateScore,
  getRiskLevel,
  getRiskColor,
  type ScanResult,
  type ScanFinding,
} from './scoring';

const CLONE_TIMEOUT = 30_000;
const SCAN_TIMEOUT = 30_000;
const COMPOSE_FILE = join(process.cwd(), 'docker-compose.scanner.yml');

const REPO_URL_RE = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(\.git)?$/;

// Patterns that may contain secrets, credentials, or PII in finding descriptions
const SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|password|token|credential|auth)[\s]*[=:]\s*['"][^'"]{4,}['"]/gi,
  /['"][A-Za-z0-9+/=]{20,}['"]/g,
  /(?:sk|pk|key|token|secret)[_-]?[a-z]*[_-][a-zA-Z0-9]{10,}/gi,
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
  /(?:\d{1,3}\.){3}\d{1,3}/g,
];

function redactString(text: string): string {
  let result = text;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

function redactFinding(finding: ScanFinding): ScanFinding {
  return {
    ...finding,
    description: redactString(finding.description),
    recommendation: redactString(finding.recommendation),
    code: finding.code ? redactString(finding.code) : finding.code,
    guardCode: finding.guardCode ? redactString(finding.guardCode) : finding.guardCode,
    // Strip full file paths to just relative filename
    file: finding.file.split('/').slice(-2).join('/'),
  };
}

export function validateRepoUrl(url: string): string | null {
  const trimmed = url.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  if (!REPO_URL_RE.test(trimmed) && !REPO_URL_RE.test(trimmed + '.git')) {
    return null;
  }
  return trimmed;
}

function extractRepoName(url: string): string {
  const parts = url.split('/');
  return parts[parts.length - 1].replace(/\.git$/, '');
}

function generateScanId(url: string): string {
  const hash = createHash('sha256')
    .update(url + Date.now().toString())
    .digest('hex');
  return hash.slice(0, 12);
}

function ensureDocker(): void {
  try {
    execFileSync('docker', ['info'], { stdio: 'pipe', timeout: 5000 });
  } catch {
    throw new Error(
      'Docker is required to scan untrusted repositories. Install Docker and run: docker compose -f docker-compose.scanner.yml build',
    );
  }
  if (!existsSync(COMPOSE_FILE)) {
    throw new Error(
      'docker-compose.scanner.yml not found. Run: docker compose -f docker-compose.scanner.yml build',
    );
  }
}

/**
 * Docker-isolated scan: clone in network container, scan in network-none container.
 * Git hooks disabled via core.hooksPath=/dev/null.
 * Each scan gets a unique volume to prevent concurrent scan collisions.
 */
function runDockerScan(repoUrl: string, repoName: string): string {
  const volumeName = `scan-work-${randomBytes(8).toString('hex')}`;
  const projectName = `scan-${randomBytes(4).toString('hex')}`;
  const composeBase = [
    'docker', 'compose',
    '-f', COMPOSE_FILE,
    '-p', projectName,
  ];

  // Create isolated volume for this scan
  execFileSync('docker', ['volume', 'create', volumeName], {
    stdio: 'pipe',
    timeout: 10_000,
  });

  try {
    // Stage 1: Clone (has network, hooks disabled, non-root)
    execFileSync(
      composeBase[0],
      [
        ...composeBase.slice(1),
        'run', '--rm',
        '-v', `${volumeName}:/work`,
        'clone', repoUrl, `/work/${repoName}`,
      ],
      { timeout: CLONE_TIMEOUT, stdio: 'pipe' },
    );

    // Stage 2: Scan (ZERO network, read-only FS, all caps dropped)
    const scanOutput = execFileSync(
      composeBase[0],
      [
        ...composeBase.slice(1),
        'run', '--rm',
        '-v', `${volumeName}:/work:ro`,
        'scan', `/work/${repoName}`, '--json',
      ],
      { timeout: SCAN_TIMEOUT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] },
    );

    return scanOutput;
  } finally {
    // Always clean up the volume, even on failure
    try {
      execFileSync('docker', ['volume', 'rm', volumeName, '-f'], {
        stdio: 'pipe',
        timeout: 10_000,
      });
    } catch {
      // Best effort cleanup
    }
  }
}

export async function runScan(repoUrl: string): Promise<ScanResult> {
  const validated = validateRepoUrl(repoUrl);
  if (!validated) {
    throw new Error('Invalid URL. Only public GitHub, GitLab, and Bitbucket repository URLs are accepted.');
  }

  // Docker is mandatory — no bare-metal fallback for untrusted code
  ensureDocker();

  const repoName = extractRepoName(validated);
  const scanId = generateScanId(validated);

  const scanOutput = runDockerScan(validated, repoName);

  let scanData;
  try {
    scanData = JSON.parse(scanOutput);
  } catch {
    throw new Error('Scanner returned invalid output. The repository may be unsupported or empty.');
  }
  const findings: ScanFinding[] = (scanData.findings || []).map(redactFinding);

  // Calculate score and risk
  const score = calculateScore(findings);
  const riskLevel = getRiskLevel(score);
  const riskColor = getRiskColor(riskLevel);

  // Count by severity
  const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const f of findings) {
    if (f.severity in summary) {
      summary[f.severity as keyof Omit<typeof summary, 'total'>]++;
    }
  }

  // Top findings (most severe first)
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const topFindings = [...findings]
    .sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4))
    .slice(0, 3);

  return {
    repoUrl: validated,
    repoName,
    score,
    riskLevel,
    riskColor,
    findings,
    summary,
    topFindings,
    scannedAt: new Date().toISOString(),
    scanId,
    filesScanned: scanData.discovery?.totalSourceFiles ?? 0,
    layersCovered: ['L0', 'L1'],
  };
}
