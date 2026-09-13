import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { once } from 'node:events';
import { chmod } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { timingSafeEqual } from 'node:crypto';
import { SealgateError, fail } from './errors.js';
import { isRecord } from './types.js';
import { RequestProtector } from './request-protection.js';

export interface GatewayOptions {
  protector: RequestProtector;
  authorization: string;
  socketPath?: string;
  /** Library/test injection only. CLI always uses api.anthropic.com. */
  upstream?: string;
  timeoutMs?: number;
  onActivity?: (event: 'inspecting' | 'forwarding' | 'blocked') => void;
}

function same(left: string, right: string): boolean {
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function reject(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message } }));
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 2 * 1024 * 1024) fail('Gateway request exceeds 2 MiB.');
    chunks.push(chunk);
  }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { fail('Gateway requires valid UTF-8 JSON.'); }
}

// Observe upstream signed blocks without changing or delaying SSE bytes. Only
// complete blocks become eligible for replay. Malformed/oversized streams never
// confer trust on a later client-supplied block.
class RemoteObserver {
  private readonly decoder = new StringDecoder('utf8');
  private pending = '';
  private readonly blocks = new Map<number, Record<string, unknown>>();
  constructor(private readonly protector: RequestProtector, private readonly sse: boolean) {}

  write(chunk: Uint8Array): void {
    this.pending += this.decoder.write(Buffer.from(chunk));
    if (this.pending.length > 2 * 1024 * 1024) fail('Gateway response event exceeds the limit.');
    if (!this.sse) return;
    let match: RegExpExecArray | null;
    while ((match = /\r?\n\r?\n/.exec(this.pending))) {
      const event = this.pending.slice(0, match.index);
      this.pending = this.pending.slice(match.index + match[0].length);
      const data = event.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
      if (!data || data === '[DONE]') continue;
      let parsed: unknown;
      try { parsed = JSON.parse(data); } catch { continue; }
      if (!isRecord(parsed) || typeof parsed.index !== 'number') continue;
      if (parsed.type === 'content_block_start' && isRecord(parsed.content_block)) {
        if (['thinking', 'redacted_thinking'].includes(String(parsed.content_block.type))) {
          if (this.blocks.size >= 64) fail('Gateway response has too many signed blocks.');
          this.blocks.set(parsed.index, { ...parsed.content_block });
        }
      } else if (parsed.type === 'content_block_delta' && isRecord(parsed.delta)) {
        const block = this.blocks.get(parsed.index); const delta = parsed.delta;
        if (!block) continue;
        if (delta.type === 'thinking_delta' && typeof delta.thinking === 'string') block.thinking = String(block.thinking ?? '') + delta.thinking;
        if (delta.type === 'signature_delta' && typeof delta.signature === 'string') block.signature = String(block.signature ?? '') + delta.signature;
        if (JSON.stringify(block).length > 2 * 1024 * 1024) fail('Gateway signed block exceeds the limit.');
      } else if (parsed.type === 'content_block_stop') {
        this.protector.rememberRemoteBlock(this.blocks.get(parsed.index)); this.blocks.delete(parsed.index);
      }
    }
  }

  end(): void {
    if (this.sse) return;
    try {
      const parsed: unknown = JSON.parse(this.pending + this.decoder.end());
      if (isRecord(parsed) && Array.isArray(parsed.content)) parsed.content.forEach(block => this.protector.rememberRemoteBlock(block));
    } catch { /* Upstream errors need no replay ledger. */ }
  }
}

export async function startGateway(options: GatewayOptions) {
  const upstream = new URL(options.upstream ?? 'https://api.anthropic.com');
  if ((upstream.protocol !== 'https:' && !(upstream.protocol === 'http:' && upstream.hostname === '127.0.0.1')) ||
      upstream.username || upstream.password || upstream.pathname !== '/' || upstream.search || upstream.hash) {
    fail('Invalid gateway upstream.');
  }
  if (!/^Bearer [^\s]+$/.test(options.authorization)) fail('Gateway requires subscription OAuth authentication.');
  const active = new Set<AbortController>();
  const server = createServer({ maxHeaderSize: 32 * 1024, requestTimeout: 300_000, headersTimeout: 15_000 }, (req, res) => {
    void handle(req, res);
  });
  server.maxConnections = 16;
  server.on('connect', (_req, socket) => socket.destroy());
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Never interpolate a request, header, provider body, or raw exception into errors.
    if (req.method === 'HEAD' && req.url === '/api/hello') { res.writeHead(204); res.end(); return; }
    if (req.method !== 'POST' || !/^\/v1\/messages(?:\/count_tokens)?(?:\?beta=true)?$/.test(req.url ?? '')) {
      reject(res, 403, 'SEALGATE blocks this endpoint.'); return;
    }
    if (!same(req.headers.authorization ?? '', options.authorization) || req.headers['x-api-key']) {
      reject(res, 401, 'SEALGATE requires the saved subscription login; sign in outside the sandbox and restart.'); return;
    }
    if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json' ||
        (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) {
      reject(res, 415, 'SEALGATE accepts uncompressed JSON only.'); return;
    }
    const version = req.headers['anthropic-version']; const beta = req.headers['anthropic-beta'];
    if (typeof version !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(version) ||
        typeof beta !== 'string' || beta.length > 4096 || !/^[a-z0-9,._ -]+$/.test(beta) ||
        !beta.split(',').some(value => /^oauth-\d{4}-\d{2}-\d{2}$/.test(value.trim()))) {
      reject(res, 400, 'SEALGATE requires Anthropic version and OAuth beta headers.'); return;
    }
    if (active.size >= 2) { reject(res, 429, 'SEALGATE gateway is busy; retry shortly.'); return; }
    const controller = new AbortController(); active.add(controller);
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 600_000);
    const abort = (): void => { if (!res.writableEnded) controller.abort(); };
    res.on('close', abort);
    try {
      const input = await readJson(req);
      options.onActivity?.('inspecting');
      const protectedRequest = await options.protector.protect(input, [version, beta], controller.signal);
      controller.signal.throwIfAborted();
      options.onActivity?.('forwarding');
      const response = await fetch(new URL(req.url!, upstream), {
        method: 'POST', redirect: 'error', signal: controller.signal,
        headers: { authorization: req.headers.authorization!, 'anthropic-version': version,
          'anthropic-beta': beta, 'content-type': 'application/json', accept: 'application/json, text/event-stream',
          'x-app': 'cli', 'user-agent': 'sealgate/0.4.0' },
        body: protectedRequest.body,
      });
      // Fetch decompresses the body. Do not forward stale length/encoding, hop-
      // by-hop headers, cookies, redirects, or a server-provided alternate route.
      const headers: Record<string, string> = { 'cache-control': 'no-store' };
      for (const name of ['content-type', 'request-id', 'retry-after', 'anthropic-ratelimit-requests-remaining',
        'anthropic-ratelimit-tokens-remaining', 'anthropic-ratelimit-requests-reset', 'anthropic-ratelimit-tokens-reset']) {
        const value = response.headers.get(name); if (value) headers[name] = value;
      }
      res.writeHead(response.status, headers);
      const observer = new RemoteObserver(options.protector, headers['content-type']?.includes('text/event-stream') ?? false);
      let bytes = 0;
      if (response.body) for await (const chunk of response.body) {
        bytes += chunk.length;
        if (bytes > 32 * 1024 * 1024) fail('Gateway response exceeds the limit.');
        if (response.ok) observer.write(chunk);
        if (!res.write(chunk)) await once(res, 'drain', { signal: controller.signal });
      }
      if (response.ok) observer.end();
      res.end();
    } catch (error) {
      options.onActivity?.('blocked');
      reject(res, error instanceof SealgateError ? 400 : 502,
        error instanceof SealgateError ? error.message : 'SEALGATE gateway request failed or timed out. No unprotected fallback was sent.');
    } finally {
      clearTimeout(timer); active.delete(controller); res.off('close', abort);
    }
  }
  await new Promise<void>((resolve, rejectStart) => {
    server.once('error', rejectStart);
    const ready = (): void => { server.off('error', rejectStart); resolve(); };
    if (options.socketPath) server.listen(options.socketPath, ready);
    else server.listen(0, '127.0.0.1', ready);
  });
  if (options.socketPath) await chmod(options.socketPath, 0o600);
  return {
    address: server.address(),
    async close(): Promise<void> {
      for (const controller of active) controller.abort();
      await new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
      options.protector.clear();
    },
  };
}
