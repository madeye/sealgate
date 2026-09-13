import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { SealgateError } from './errors.js';
import { isRecord } from './types.js';

const execute = promisify(execFile);

/** The host enumerates live PIDs; only the confined supervisor sends cleanup
 * signals. Kernel sandbox membership survives double-fork, setsid and exec. */
export function supervisedSeatbelt(command: string, args: string[], env: Record<string, string>, cwd: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, cwd, stdio: ['inherit', 'inherit', 'inherit', 'ipc'] });
    let code: number | undefined;
    let finishing = false;
    let sweeps = 0;
    let error: Error | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const failed = (): void => {
      error ??= new SealgateError('Could not supervise or clean up the macOS sandbox session.');
      child.kill('SIGKILL');
    };
    const send = (message: object): void => {
      if (child.connected) child.send(message, err => { if (err) failed(); });
      else failed();
    };
    const sweep = async (): Promise<void> => {
      try {
        if (++sweeps > 50) { failed(); return; }
        // No argv, environments or credentials are requested or logged.
        const { stdout } = await execute('/bin/ps', ['-U', String(process.getuid!()), '-o', 'pid=,stat='],
          { env: { PATH: '/usr/bin:/bin' }, timeout: 2000, maxBuffer: 4 * 1024 * 1024 });
        const pids = stdout.split('\n').flatMap(line => {
          const match = /^\s*(\d+)\s+(\S+)/.exec(line);
          return match && !match[2].includes('Z') ? [Number(match[1])] : [];
        });
        if (!pids.includes(child.pid!)) throw new Error('Missing supervisor');
        send({ type: 'reap', pids });
      } catch { failed(); }
    };
    const interrupt = (): void => send({ type: 'stop', signal: 'SIGINT' });
    const terminate = (): void => send({ type: 'stop', signal: 'SIGTERM' });
    process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
    child.on('message', (message: unknown) => {
      if (!isRecord(message)) { failed(); return; }
      if (message.type === 'exit' && code === undefined && Number.isInteger(message.code)) {
        code = Number(message.code);
        deadline = setTimeout(failed, 10_000);
        void sweep();
      } else if (message.type === 'reaped' && code !== undefined && !finishing) {
        if (message.killed === 0) { finishing = true; send({ type: 'finish', code }); }
        else void delay(25).then(sweep);
      } else failed();
    });
    child.once('error', failed);
    child.once('close', status => {
      clearTimeout(deadline);
      process.off('SIGINT', interrupt); process.off('SIGTERM', terminate);
      if (error || !finishing) reject(error ?? new SealgateError('The macOS sandbox supervisor exited unexpectedly.'));
      else resolve(status ?? 1);
    });
  });
}
