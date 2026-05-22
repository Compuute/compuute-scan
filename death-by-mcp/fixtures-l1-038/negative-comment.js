// Fixture: only references npx inside comments — should NOT be flagged.
// Example call (do NOT do this): spawn('npx', spawnArgs)
/* spawn('npx', spawnArgs) — commented out for safety */
function noOp() {
  return null;
}

module.exports = { noOp };
