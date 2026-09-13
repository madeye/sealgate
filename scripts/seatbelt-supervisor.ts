// Executed by Node inside the session's Seatbelt profile, with a private IPC
// channel to the host. Never execute cleanup in the unconfined host process.
import { spawn } from 'node:child_process';
import { constants } from 'node:os';

function confined(): boolean {
  if (process.platform !== 'darwin' || !process.send || process.ppid <= 1) return false;
  try { process.kill(process.ppid, 0); return false; }
  catch (error) { return (error as NodeJS.ErrnoException).code === 'EPERM'; }
}
if (!confined()) {
  process.stderr.write('SEALGATE supervisor requires an isolated sandbox and host IPC.\n');
  process.exit(1);
}

let exited = false;
let timer: ReturnType<typeof setTimeout> | undefined;
const child = spawn(process.argv[1], process.argv.slice(2), { stdio: 'inherit' });
const ended = (code: number): void => {
  if (exited) return;
  exited = true; clearTimeout(timer);
  process.send!({ type: 'exit', code });
};
child.once('error', () => ended(1));
child.once('exit', (code, signal) => ended(code ?? (signal ? 128 + constants.signals[signal] : 1)));
const stop = (signal: 'SIGINT' | 'SIGTERM'): void => {
  if (exited) return;
  child.kill(signal);
  // A client ignoring termination must not hold the session open indefinitely.
  timer ??= setTimeout(() => ended(signal === 'SIGINT' ? 130 : 143), 1500);
};
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
process.on('message', (message: unknown) => {
  if (!message || typeof message !== 'object') return;
  const value = message as { type?: string; signal?: string; pids?: unknown; code?: unknown };
  if (value.type === 'stop' && (value.signal === 'SIGINT' || value.signal === 'SIGTERM')) stop(value.signal);
  if (value.type === 'reap' && exited && Array.isArray(value.pids)) {
    let killed = 0;
    for (const pid of value.pids) {
      if (!Number.isSafeInteger(pid) || pid <= 1 || pid === process.pid || pid === process.ppid) continue;
      try {
        // The kernel enforces (target same-sandbox) for each signal, even after
        // reparenting/setsid. Unrelated host processes and other sessions fail.
        process.kill(pid, 'SIGSTOP');
        process.kill(pid, 'SIGKILL');
        killed++;
      } catch (error) {
        if (!['EPERM', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) process.exit(1);
      }
    }
    process.send!({ type: 'reaped', killed });
  }
  if (value.type === 'finish' && exited && Number.isInteger(value.code)) process.exit(Number(value.code));
});
