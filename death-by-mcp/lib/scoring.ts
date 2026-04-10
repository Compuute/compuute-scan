export interface ScanFinding {
  id: string;
  title: string;
  layer: string;
  severity: string;
  file: string;
  line: number;
  description: string;
  recommendation: string;
  owasp?: string;
  nis2?: string;
  guardDetected?: boolean;
  originalSeverity?: string;
}

export interface ScanResult {
  repoUrl: string;
  repoName: string;
  score: number;
  riskLevel: 'clean' | 'low' | 'medium' | 'high' | 'critical';
  riskColor: string;
  findings: ScanFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  topFindings: ScanFinding[];
  scannedAt: string;
  scanId: string;
  filesScanned: number;
  layersCovered: string[];
}

export function calculateScore(findings: ScanFinding[]): number {
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

export function getRiskLevel(score: number): ScanResult['riskLevel'] {
  if (score === 0) return 'clean';
  if (score <= 15) return 'low';
  if (score <= 40) return 'medium';
  if (score <= 70) return 'high';
  return 'critical';
}

export function getRiskColor(level: ScanResult['riskLevel']): string {
  switch (level) {
    case 'clean': return '#22c55e';
    case 'low': return '#eab308';
    case 'medium': return '#f97316';
    case 'high': return '#ef4444';
    case 'critical': return '#dc2626';
  }
}

export function getRiskLabel(level: ScanResult['riskLevel']): string {
  switch (level) {
    case 'clean': return 'Clean';
    case 'low': return 'Low Risk';
    case 'medium': return 'Medium Risk';
    case 'high': return 'High Risk';
    case 'critical': return 'Critical Risk';
  }
}
