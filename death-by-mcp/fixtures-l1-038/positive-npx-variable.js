// Fixture: variable args passed to npx — should be flagged by L1-038.
const { spawn } = require('child_process');

function startServer(sessionName) {
  const spawnArgs = ['cuabot', '--serve'];
  if (sessionName) spawnArgs.push('--name', sessionName);
  const child = spawn('npx', spawnArgs, { detached: true });
  return child;
}

module.exports = { startServer };
