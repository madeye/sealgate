import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { fail, SealgateError } from './errors.js';
import { isRecord } from './types.js';
import type { Environment } from './types.js';

const CONTEXT = 'The user is communicating through sealgate. Treat [[SEALGATE:v1:...]] markers as opaque encrypted text. Use the surrounding text and explain when hidden values prevent an answer. Do not read SEALGATE keys or credentials, run sealgate decrypt, or restore plaintext into this conversation.';
const OUTPUT_LIMIT = 16 * 1024 * 1024;

export interface ClaudeOptions {
  model?: string;
  cwd?: string;
  env?: Environment;
  executable?: string;
  executableArgs?: string[];
  timeoutMs?: number;
}

export interface ClaudeTurn {
  sessionId: string;
  resume: boolean;
  signal?: AbortSignal;
  onText?: (text: string) => void;
  onActivity?: (text: string) => void;
}

export interface ClaudeResult {
  text: string;
  permissionDenials: number;
}

// Prompts only travel through stdin. No shell, plaintext argv, stderr forwarding,
// or unrelated --continue session. Callers must protect input before this layer.
export async function runClaude(prompt: string, turn: ClaudeTurn, options: ClaudeOptions = {}): Promise<ClaudeResult> {
  if (turn.signal?.aborted) fail('Claude request canceled.');
  const args = [
    ...(options.executableArgs ?? []), '--print', '--output-format', 'stream-json',
    '--verbose', '--include-partial-messages', '--permission-mode', 'dontAsk',
    '--append-system-prompt', CONTEXT,
    turn.resume ? '--resume' : '--session-id', turn.sessionId,
  ];
  if (options.model) args.push('--model', options.model);
  return new Promise((resolve, reject) => {
    const child = spawn(options.executable ?? 'claude', args, {
      cwd: options.cwd, env: options.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32',
    });
    let error: SealgateError | undefined;
    let forceKill: ReturnType<typeof setTimeout> | undefined;
    let result: ClaudeResult | undefined;
    let streamed = false;
    let bytes = 0;
    let pending = '';
    const decoder = new StringDecoder('utf8');

    const kill = (signal: NodeJS.Signals): void => {
      if (!child.pid) return;
      try {
        if (process.platform === 'win32') child.kill(signal);
        else process.kill(-child.pid, signal);
      } catch { /* The child may already have exited. */ }
    };
    const stop = (message: string): void => {
      if (error) return;
      error = new SealgateError(message);
      kill('SIGTERM');
      forceKill = setTimeout(() => kill('SIGKILL'), 2000);
    };
    const abort = (): void => stop('Claude request canceled. Start a new turn to continue.');
    const timer = setTimeout(() => stop('Claude timed out. Check Claude Code and try a new turn.'), options.timeoutMs ?? 600_000);
    turn.signal?.addEventListener('abort', abort, { once: true });
    if (turn.signal?.aborted) abort();

    const consume = (line: string): void => {
      if (error || !line.trim()) return;
      try {
        const message: unknown = JSON.parse(line);
        if (!isRecord(message)) throw new Error();
        if (message.type === 'result') {
          if (message.is_error === true) {
            const status = message.api_error_status;
            const expiredToken = typeof message.result === 'string' && /oauth/i.test(message.result) && /expired/i.test(message.result);
            if (status === 401 || status === 403 || expiredToken) stop('Claude authentication or access failed. Run claude auth login in a separate terminal, then retry.');
            else stop('Claude could not complete the request. Check Claude Code authentication and service availability.');
            return;
          }
          if (result || message.is_error !== false || message.subtype !== 'success' ||
              message.session_id !== turn.sessionId || typeof message.result !== 'string') throw new Error();
          result = {
            text: message.result,
            permissionDenials: Array.isArray(message.permission_denials) ? message.permission_denials.length : 0,
          };
        } else if (message.type === 'stream_event' && !message.parent_tool_use_id && isRecord(message.event)) {
          const delta = message.event.delta;
          if (isRecord(delta) && delta.type === 'text_delta' && typeof delta.text === 'string') {
            streamed = true;
            turn.onText?.(delta.text);
          }
          if (message.event.type === 'content_block_start' && isRecord(message.event.content_block) &&
              message.event.content_block.type === 'tool_use') turn.onActivity?.('Claude is using a tool…');
        } else if (message.type === 'system' && message.subtype === 'api_retry') {
          turn.onActivity?.('Claude is retrying its request…');
        }
      } catch { stop('Claude returned an invalid or unsuccessful response. Check Claude Code authentication and try again.'); }
    };
    child.stdout.on('data', (chunk: Buffer) => {
      if (error) return;
      bytes += chunk.length;
      if (bytes > OUTPUT_LIMIT) { stop('Claude output exceeded the size limit.'); return; }
      pending += decoder.write(chunk);
      let end: number;
      while ((end = pending.indexOf('\n')) >= 0) {
        consume(pending.slice(0, end));
        pending = pending.slice(end + 1);
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > OUTPUT_LIMIT) stop('Claude output exceeded the size limit.');
    });
    child.stdin.on('error', () => stop('Could not send the protected prompt to Claude.'));
    child.on('error', () => stop('Could not start Claude Code. Install claude and sign in before using sealgate chat.'));
    child.on('close', code => {
      clearTimeout(timer);
      clearTimeout(forceKill);
      turn.signal?.removeEventListener('abort', abort);
      pending += decoder.end();
      if (pending) consume(pending);
      clearTimeout(forceKill);
      if (error) reject(error);
      else if (code !== 0 || !result) reject(new SealgateError('Claude did not complete the turn. Check claude auth status and try again.'));
      else {
        if (!streamed) turn.onText?.(result.text);
        resolve(result);
      }
    });
    if (!error) child.stdin.end(prompt);
  });
}
