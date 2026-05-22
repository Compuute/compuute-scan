// Fixture: pnpx with variable args — should be flagged by L1-038.
import { execFile } from 'child_process';

export function invoke(pkgArgs: string[]): void {
  execFile('pnpx', pkgArgs, (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}
