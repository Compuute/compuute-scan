// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const VERSION = '0.5.0';
const MAX_FILE_SIZE = 500 * 1024; // 500 KB
const MAX_CODE_SNIPPET = 120; // max characters in code/guardCode snippets
const GUARD_WINDOW = 15; // lines above/below to check for guards

const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.py', '.mjs', '.cjs', '.tsx', '.jsx', '.go', '.rs',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  'coverage', '.turbo', '.next', '.venv', 'venv', 'vendor',
]);

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Inline suppression: place on the line ABOVE a finding to suppress it
// Supports: // compuute-scan-ignore-next-line
//           // compuute-scan-ignore-next-line L1-006
//           # compuute-scan-ignore-next-line (Python)
const IGNORE_PATTERN = /(?:\/\/|#)\s*compuute-scan-ignore-next-line(?:\s+(L\d+-\d+))?/;
