// ─────────────────────────────────────────────
// Guard Check System
// ─────────────────────────────────────────────

// Function definition patterns for boundary detection
const FUNC_DEF_PATTERNS = [
  // JS/TS: function name(...), async function, arrow functions assigned
  /^\s*(?:export\s+)?(?:async\s+)?function\s+\w+\s*\(/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>/,
  /^\s*(?:async\s+)?(?:\w+)\s*\([^)]*\)\s*\{/,
  // Python: def name(
  /^\s*(?:async\s+)?def\s+\w+\s*\(/,
  // Go: func name(
  /^\s*func\s+(?:\([^)]*\)\s+)?\w+\s*\(/,
];

/**
 * Finds the enclosing function boundaries around a given line index.
 * Uses brace counting for JS/TS/Go and indent-based detection for Python.
 * Returns { start, end } line indices or null if not inside a function.
 */
function findFunctionBounds(lines, lineIdx) {
  // Walk backwards to find the nearest function definition
  let funcStart = -1;
  for (let i = lineIdx; i >= 0; i--) {
    for (const pat of FUNC_DEF_PATTERNS) {
      if (pat.test(lines[i])) {
        funcStart = i;
        break;
      }
    }
    if (funcStart >= 0) break;
  }
  if (funcStart < 0) return null;

  const funcLine = lines[funcStart];

  // Python: indent-based
  if (/^\s*(?:async\s+)?def\s+/.test(funcLine)) {
    const defIndent = funcLine.match(/^(\s*)/)[1].length;
    let funcEnd = funcStart;
    for (let i = funcStart + 1; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed === '' || trimmed.startsWith('#')) { funcEnd = i; continue; }
      const indent = lines[i].match(/^(\s*)/)[1].length;
      if (indent <= defIndent) break;
      funcEnd = i;
    }
    return { start: funcStart, end: funcEnd };
  }

  // JS/TS/Go: brace-based
  let braceDepth = 0;
  let foundOpen = false;
  for (let i = funcStart; i < lines.length; i++) {
    const line = lines[i];
    for (let c = 0; c < line.length; c++) {
      if (line[c] === '{') { braceDepth++; foundOpen = true; }
      else if (line[c] === '}') { braceDepth--; }
    }
    if (foundOpen && braceDepth <= 0) {
      return { start: funcStart, end: i };
    }
  }
  // Unclosed — fallback to null
  return null;
}

/**
 * Checks if there's a mitigation/guard pattern near the matched line.
 * First tries function-boundary-aware search (entire enclosing function).
 * Falls back to GUARD_WINDOW lines above/below.
 * Returns { mitigated: bool, guardLine: number|null, guardCode: string|null }
 */
function checkGuard(lines, matchLineIdx, guardPatterns, guardWindow) {
  const window = guardWindow || GUARD_WINDOW;

  // Try function-boundary-aware search first
  const bounds = findFunctionBounds(lines, matchLineIdx);
  const start = bounds ? bounds.start : Math.max(0, matchLineIdx - window);
  const end = bounds ? bounds.end : Math.min(lines.length - 1, matchLineIdx + window);

  for (let i = start; i <= end; i++) {
    if (i === matchLineIdx) continue;
    const line = lines[i];
    for (const gp of guardPatterns) {
      if (gp.test(line)) {
        return {
          mitigated: true,
          guardLine: i + 1,
          guardCode: line.trim().substring(0, MAX_CODE_SNIPPET),
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
