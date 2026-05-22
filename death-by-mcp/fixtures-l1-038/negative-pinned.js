// Fixture: pinned package + shell:false — should NOT be flagged.
const { spawn } = require('child_process');

function runPinned() {
  return spawn('npx', ['--package=@compuute/pinned@1.2.3', '--', 'serve'], {
    shell: false,
  });
}

module.exports = { runPinned };
