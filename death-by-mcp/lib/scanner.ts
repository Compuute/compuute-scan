import { execSync, execFileSync } from 'child_process';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createHash } from 'crypto';
import {
  calculateScore,
  getRiskLevel,
  getRiskColor,
  type ScanResult,
  type ScanFinding,
} from './scoring';

const CLONE_TIMEOUT = 30_000;
const SCAN_TIMEOUT = 30_000;
const MAX_REPO_SIZE_MB = 100;
const SCANNER_PATH = join(process.cwd(), 'lib', 'compuute-scan.js');

const GITHUB_URL_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/;

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
    // Strip full file paths to just relative filename
    file: finding.file.split('/').slice(-2).join('/'),
  };
}

export function validateRepoUrl(url: string): string | null {
  const trimmed = url.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  if (!GITHUB_URL_RE.test(trimmed) && !GITHUB_URL_RE.test(trimmed + '.git')) {
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

export async function runScan(repoUrl: string): Promise<ScanResult> {
  const validated = validateRepoUrl(repoUrl);
  if (!validated) {
    throw new Error('Invalid URL. Only public GitHub repository URLs are accepted.');
  }

  const repoName = extractRepoName(validated);
  const scanId = generateScanId(validated);
  const tmpDir = mkdtempSync(join(tmpdir(), 'mcp-scan-'));
  const repoDir = join(tmpDir, repoName);

  try {
    // Shallow clone
    execFileSync('git', ['clone', '--depth', '1', validated, repoDir], {
      timeout: CLONE_TIMEOUT,
      stdio: 'pipe',
    });

    // Check repo size
    const sizeOutput = execSync(`du -sm "${repoDir}" | cut -f1`, {
      encoding: 'utf-8',
      timeout: 5000,
    }).trim();
    const sizeMB = parseInt(sizeOutput, 10);
    if (sizeMB > MAX_REPO_SIZE_MB) {
      throw new Error(`Repository too large (${sizeMB}MB). Maximum is ${MAX_REPO_SIZE_MB}MB.`);
    }

    // Run compuute-scan
    const scanOutput = execFileSync('node', [SCANNER_PATH, repoDir, '--json'], {
      timeout: SCAN_TIMEOUT,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const scanData = JSON.parse(scanOutput);
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
  } finally {
    // Always clean up
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }
}
