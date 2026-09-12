import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import type { IncomingMessage, RequestListener, ServerResponse } from 'node:http';
import type { TestContext } from 'node:test';
import type { Environment } from '../src/types.js';

export const root = fileURLToPath(new URL('../../', import.meta.url));
export const compiledRoot = fileURLToPath(new URL('../', import.meta.url));

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

interface ChatRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  response_format: { type: string };
  stream: boolean;
}

export async function temporary(t: TestContext): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hecc-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

export async function provider(t: TestContext, handler: RequestListener): Promise<string> {
  const server = createServer(handler);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => {
    server.close(() => resolve());
    server.closeAllConnections();
  }));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected a TCP mock provider.');
  return `http://127.0.0.1:${address.port}/v1`;
}

export function answer(res: ServerResponse, content: unknown, extra: Record<string, unknown> = {}): void {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ choices: [{
    finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(content) }, ...extra,
  }] }));
}

export async function requestBody(req: IncomingMessage): Promise<ChatRequest> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as ChatRequest;
}

export function cli(args: string[], input: string | Buffer, dir: string, extraEnv: Environment = {}): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const inheritedEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('HECC_')));
    const child = spawn(process.execPath, [path.join(compiledRoot, 'bin/hecc.js'), ...args], {
      cwd: dir,
      env: { ...inheritedEnv, HECC_CONFIG_DIR: dir, HECC_TEST_API_KEY: 'synthetic-provider-key', ...extraEnv },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.stdin.on('error', (error: NodeJS.ErrnoException) => { if (error.code !== 'EPIPE') reject(error); });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }));
    child.stdin.end(input);
  });
}
