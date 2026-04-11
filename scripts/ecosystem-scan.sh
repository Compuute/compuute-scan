#!/bin/bash
# ecosystem-scan.sh — Scan multiple MCP server repos and produce anonymous aggregate statistics
#
# Usage:
#   ./scripts/ecosystem-scan.sh repos.txt [output.json]
#
# Input format (repos.txt):
#   https://github.com/org/repo1
#   https://github.com/org/repo2
#   ...
#
# Output: Anonymous JSON with aggregate statistics only.
# No repo names, no code snippets, no identifying information.
#
# Requires: Docker (each scan runs in isolated containers)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/../compuute-scan.js"
REPOS_FILE="${1:-}"
OUTPUT_FILE="${2:-ecosystem-report.json}"

if [[ -z "$REPOS_FILE" || ! -f "$REPOS_FILE" ]]; then
  echo "Usage: $0 <repos.txt> [output.json]"
  echo ""
  echo "repos.txt should contain one GitHub/GitLab/Bitbucket URL per line."
  exit 1
fi

if ! command -v node &>/dev/null; then
  echo "Error: Node.js is required"
  exit 1
fi

if ! command -v git &>/dev/null; then
  echo "Error: git is required"
  exit 1
fi

# Counters
total=0
scanned=0
failed=0
critical_total=0
high_total=0
medium_total=0
low_total=0
repos_with_critical=0
repos_with_findings=0
repos_clean=0

# Rule frequency tracking (stored as "rule_id:count" lines in a temp file)
RULE_COUNTS=$(mktemp)
trap 'rm -f "$RULE_COUNTS"' EXIT

echo "Ecosystem scan starting..."
echo "Input: $REPOS_FILE"
echo "Output: $OUTPUT_FILE"
echo ""

while IFS= read -r url || [[ -n "$url" ]]; do
  # Skip empty lines and comments
  url=$(echo "$url" | tr -d '\r' | xargs)
  [[ -z "$url" || "$url" == \#* ]] && continue

  total=$((total + 1))
  repo_name=$(basename "$url" .git)
  echo "[$total] Scanning: $repo_name..."

  # Clone to temp dir (shallow, hooks disabled)
  TMPDIR=$(mktemp -d)
  if ! git clone --depth 1 --config core.hooksPath=/dev/null "$url" "$TMPDIR/repo" &>/dev/null; then
    echo "  SKIP: Clone failed (private or unavailable)"
    failed=$((failed + 1))
    rm -rf "$TMPDIR"
    continue
  fi

  # Run scanner
  SCAN_OUTPUT=$(node "$SCANNER" "$TMPDIR/repo" --json 2>/dev/null || true)
  rm -rf "$TMPDIR"

  if [[ -z "$SCAN_OUTPUT" || "$SCAN_OUTPUT" == "null" ]]; then
    echo "  SKIP: Scan produced no output"
    failed=$((failed + 1))
    continue
  fi

  # Parse results (anonymous — only counts, no code)
  result=$(node -e "
    try {
      const d = JSON.parse(process.argv[1]);
      const s = d.summary || {};
      const c = s.critical || 0;
      const h = s.high || 0;
      const m = s.medium || 0;
      const l = s.low || 0;
      const total = (d.findings || []).length;
      // Count rules
      const rules = {};
      for (const f of (d.findings || [])) {
        rules[f.id] = (rules[f.id] || 0) + 1;
      }
      console.log(JSON.stringify({ c, h, m, l, total, rules }));
    } catch { console.log('{}'); }
  " "$SCAN_OUTPUT" 2>/dev/null)

  if [[ "$result" == "{}" ]]; then
    echo "  SKIP: Parse failed"
    failed=$((failed + 1))
    continue
  fi

  scanned=$((scanned + 1))

  # Extract counts
  c=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.c||0)")
  h=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.h||0)")
  m=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.m||0)")
  l=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.l||0)")
  t=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.total||0)")

  critical_total=$((critical_total + c))
  high_total=$((high_total + h))
  medium_total=$((medium_total + m))
  low_total=$((low_total + l))

  if [[ "$c" -gt 0 ]]; then
    repos_with_critical=$((repos_with_critical + 1))
  fi
  if [[ "$t" -gt 0 ]]; then
    repos_with_findings=$((repos_with_findings + 1))
  else
    repos_clean=$((repos_clean + 1))
  fi

  # Accumulate rule counts
  echo "$result" | node -e "
    const d=JSON.parse(require('fs').readFileSync(0,'utf8'));
    for (const [id,count] of Object.entries(d.rules||{})) {
      console.log(id + ':' + count);
    }
  " >> "$RULE_COUNTS"

  echo "  Done: $t findings (C:$c H:$h M:$m L:$l)"

done < "$REPOS_FILE"

# Aggregate rule counts
rule_summary=$(node -e "
  const fs = require('fs');
  const lines = fs.readFileSync('$RULE_COUNTS','utf8').trim().split('\n').filter(Boolean);
  const counts = {};
  for (const line of lines) {
    const [id, count] = line.split(':');
    counts[id] = (counts[id] || 0) + parseInt(count, 10);
  }
  // Sort by count descending
  const sorted = Object.entries(counts).sort((a,b) => b[1] - a[1]);
  console.log(JSON.stringify(Object.fromEntries(sorted)));
")

# Generate anonymous report
finding_total=$((critical_total + high_total + medium_total + low_total))
pct_with_findings=$(node -e "console.log($scanned > 0 ? ($repos_with_findings / $scanned * 100).toFixed(1) : '0.0')")
pct_with_critical=$(node -e "console.log($scanned > 0 ? ($repos_with_critical / $scanned * 100).toFixed(1) : '0.0')")

cat > "$OUTPUT_FILE" << JSONEOF
{
  "meta": {
    "tool": "compuute-scan",
    "version": "0.5.0",
    "date": "$(date -u +%Y-%m-%d)",
    "disclaimer": "Anonymous aggregate statistics only. No repository names, code, or identifying information included."
  },
  "summary": {
    "totalRepos": $total,
    "scannedSuccessfully": $scanned,
    "scanFailed": $failed,
    "reposWithFindings": $repos_with_findings,
    "reposClean": $repos_clean,
    "reposWithCritical": $repos_with_critical,
    "pctWithFindings": $pct_with_findings,
    "pctWithCritical": $pct_with_critical
  },
  "findings": {
    "total": $finding_total,
    "critical": $critical_total,
    "high": $high_total,
    "medium": $medium_total,
    "low": $low_total,
    "avgPerRepo": $(node -e "console.log($scanned > 0 ? ($finding_total / $scanned).toFixed(1) : '0.0')")
  },
  "topRules": $rule_summary
}
JSONEOF

echo ""
echo "═══════════════════════════════════════════"
echo "  Ecosystem Scan Complete"
echo "═══════════════════════════════════════════"
echo "  Repos scanned:   $scanned / $total"
echo "  Total findings:  $finding_total"
echo "  With findings:   $repos_with_findings ($pct_with_findings%)"
echo "  With critical:   $repos_with_critical ($pct_with_critical%)"
echo "  Clean:           $repos_clean"
echo ""
echo "  Report: $OUTPUT_FILE"
echo "═══════════════════════════════════════════"
