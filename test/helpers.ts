import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as createNetServer, connect as netConnect } from 'node:net';
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
  chat_template_kwargs?: { enable_thinking: boolean };
}

export async function temporary(t: TestContext): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'sealgate-test-'));
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
    const inheritedEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('SEALGATE_')));
    const child = spawn(process.execPath, [path.join(compiledRoot, 'bin/sealgate.js'), ...args], {
      cwd: dir,
      env: { ...inheritedEnv, SEALGATE_CONFIG_DIR: dir, SEALGATE_TEST_API_KEY: 'synthetic-provider-key', ...extraEnv },
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

export interface MockProxy {
  url: string;
  /** CONNECT authorities received, in order. */
  log: string[];
  authorizations: Array<string | undefined>;
}

/** A minimal HTTP CONNECT proxy. `resolve` maps a requested authority to a local
 * target, or returns undefined to refuse it with 403. */
export async function mockProxy(t: TestContext, resolve: (host: string, port: number) => { host: string; port: number } | undefined): Promise<MockProxy> {
  const log: string[] = []; const authorizations: Array<string | undefined> = [];
  const server = createNetServer(client => {
    let head = '';
    const onData = (chunk: Buffer): void => {
      head += chunk.toString('latin1');
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      client.off('data', onData);
      const lines = head.slice(0, end).split('\r\n');
      const match = /^CONNECT (\[[^\]]+\]|[^:\s]+):(\d+) HTTP\/1\.1$/.exec(lines[0]);
      const auth = lines.find(line => /^proxy-authorization:/i.test(line))?.split(':').slice(1).join(':').trim();
      authorizations.push(auth);
      if (!match) { client.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return; }
      log.push(`${match[1]}:${match[2]}`);
      const target = resolve(match[1], Number(match[2]));
      if (!target) { client.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
      const upstream = netConnect(target, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        const rest = head.slice(end + 4);
        if (rest) upstream.write(Buffer.from(rest, 'latin1'));
        client.pipe(upstream).pipe(client);
      });
      upstream.on('error', () => client.destroy()); client.on('error', () => upstream.destroy());
      client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy());
    };
    client.on('data', onData);
    client.on('error', () => {});
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected a TCP mock proxy.');
  return { url: `http://127.0.0.1:${address.port}`, log, authorizations };
}

export const fixtures = fileURLToPath(new URL('../../test/fixtures/', import.meta.url));
