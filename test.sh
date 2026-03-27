#!/bin/bash
# compuute-scan test suite
# Tests against Appsecco vulnerable MCP servers lab

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="$SCRIPT_DIR/compuute-scan.js"
EXAMPLES_DIR="$SCRIPT_DIR/examples"
LAB_DIR="$SCRIPT_DIR/test-repos/vulnerable-mcp-servers-lab"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "════════════════════════════════════════════"
echo " compuute-scan v0.1.0 — Test Suite"
echo "════════════════════════════════════════════"
echo ""

# Step 1: Clone test repos if needed
if [ ! -d "$LAB_DIR" ]; then
  echo "Cloning vulnerable-mcp-servers-lab..."
  mkdir -p "$SCRIPT_DIR/test-repos"
  git clone https://github.com/appsecco/vulnerable-mcp-servers-lab.git "$LAB_DIR" 2>/dev/null || {
    echo -e "${YELLOW}Warning: Could not clone lab repo. Checking local copy...${NC}"
    # Try the user's existing copy
    if [ -d "$HOME/DevWorkspace/projects/mcp-security-lab/vulnerable-mcp-servers-lab" ]; then
      LAB_DIR="$HOME/DevWorkspace/projects/mcp-security-lab/vulnerable-mcp-servers-lab"
      echo "Using local copy at $LAB_DIR"
    else
      echo -e "${RED}No test repos available. Skipping tests.${NC}"
      exit 1
    fi
  }
fi

mkdir -p "$EXAMPLES_DIR"

# Test runner function
run_test() {
  local name="$1"
  local dir="$2"
  local expect_layer="$3"
  local min_findings="$4"

  TOTAL=$((TOTAL + 1))

  if [ ! -d "$dir" ]; then
    echo -e "${YELLOW}SKIP${NC} $name — directory not found"
    return
  fi

  local output_file="$EXAMPLES_DIR/${name}-scan.md"
  local json_file="$EXAMPLES_DIR/${name}-scan.json"

  # Run scanner (markdown)
  node "$SCANNER" "$dir" --output "$output_file" 2>/dev/null

  # Run scanner (json) for validation
  local json_output
  json_output=$(node "$SCANNER" "$dir" --json 2>/dev/null)

  # Parse finding count from JSON
  local finding_count
  finding_count=$(echo "$json_output" | node -e "
    let data = '';
    process.stdin.on('data', d => data += d);
    process.stdin.on('end', () => {
      try {
        const j = JSON.parse(data);
        console.log(j.findings.length);
      } catch(e) {
        console.log(0);
      }
    });
  ")

  # Parse layer-specific findings
  local layer_count
  layer_count=$(echo "$json_output" | node -e "
    let data = '';
    process.stdin.on('data', d => data += d);
    process.stdin.on('end', () => {
      try {
        const j = JSON.parse(data);
        const count = j.findings.filter(f => f.layer === '${expect_layer}').length;
        console.log(count);
      } catch(e) {
        console.log(0);
      }
    });
  ")

  if [ "$finding_count" -ge "$min_findings" ] && [ "$layer_count" -ge 1 ]; then
    echo -e "${GREEN}PASS${NC} $name — $finding_count findings ($layer_count in $expect_layer)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC} $name — $finding_count findings ($layer_count in $expect_layer, expected >= $min_findings total)"
    FAIL=$((FAIL + 1))
  fi
}

echo "Running scans against vulnerable MCP servers..."
echo ""

# Test each vulnerable server
run_test "filesystem-workspace-actions" \
  "$LAB_DIR/vulnerable-mcp-server-filesystem-workspace-actions" \
  "L1" 1

run_test "indirect-prompt-injection" \
  "$LAB_DIR/vulnerable-mcp-server-indirect-prompt-injection" \
  "L3" 1

run_test "indirect-prompt-injection-remote" \
  "$LAB_DIR/vulnerable-mcp-server-indirect-prompt-injection-remote-mcp" \
  "L1" 1

run_test "malicious-tools" \
  "$LAB_DIR/vulnerable-mcp-server-malicious-tools" \
  "L3" 1

run_test "secrets-pii" \
  "$LAB_DIR/vulnerable-mcp-server-secrets-pii" \
  "L2" 1

run_test "malicious-code-exec" \
  "$LAB_DIR/vulnerable-mcp-server-malicious-code-exec" \
  "L1" 1

run_test "namespace-typosquatting" \
  "$LAB_DIR/vulnerable-mcp-server-namespace-typosquatting" \
  "L3" 1

run_test "outdated-packages" \
  "$LAB_DIR/vulnerable-mcp-server-outdated-pacakges" \
  "L3" 1

run_test "wikipedia-http-streamable" \
  "$LAB_DIR/vulnerable-mcp-server-wikipedia-http-streamable" \
  "L1" 1

echo ""
echo "════════════════════════════════════════════"
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} / ${TOTAL} total"
echo "════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}Some tests failed.${NC}"
  exit 1
else
  echo -e "${GREEN}All tests passed!${NC}"
  echo "Reports saved to $EXAMPLES_DIR/"
  exit 0
fi
