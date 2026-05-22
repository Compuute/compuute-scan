// Fixture: template literal in args — should be flagged by L1-038.
const { spawnSync } = require('child_process');

function runPackage(pkg, args) {
  return spawnSync('pipx', [`run`, `${pkg}`, ...args]);
}

module.exports = { runPackage };
