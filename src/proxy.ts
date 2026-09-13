import { BlockList, createConnection, createServer, isIP } from 'node:net';
import type { Socket } from 'node:net';
import { chmod } from 'node:fs/promises';
import { fail } from './errors.js';
import type { Environment } from './types.js';

const HEAD_LIMIT = 8 * 1024;

function bare(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
}

export function isLoopback(hostname: string): boolean {
  const host = bare(hostname).toLowerCase();
  return host === 'localhost' || host === '::1' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(host);
}

/** Only plain HTTP CONNECT proxies with a host and port. Anything else fails
 * closed rather than silently connecting directly. */
export function parseProxyUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { fail('Proxy environment variable must be an http://host:port URL.'); }
  if (url.protocol !== 'http:' || !url.hostname || (url.pathname !== '/' && url.pathname !== '') ||
      url.search || url.hash || isIP(bare(url.hostname)) === 0 && !/^[a-z0-9.-]+$/i.test(url.hostname)) {
    fail('Proxy environment variable must be an http://host:port URL.');
  }
  return url;
}

export function proxyPort(proxy: URL): number {
  return proxy.port ? Number(proxy.port) : 80;
}

function bypassed(target: URL, list: string): boolean {
  const host = bare(target.hostname).toLowerCase();
  const port = target.port || (target.protocol === 'https:' ? '443' : '80');
  const ip = isIP(host);
  for (const raw of list.split(/[\s,]+/)) {
    let entry = raw.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;
    let entryPort: string | undefined;
    const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(entry);
    if (bracket) { entry = bracket[1]; entryPort = bracket[2]; }
    else if (!entry.includes('/') && /^(.*):(\d+)$/.test(entry) && (entry.match(/:/g) ?? []).length === 1) {
      const match = /^(.*):(\d+)$/.exec(entry)!; entry = match[1]; entryPort = match[2];
    }
    if (entryPort && entryPort !== port) continue;
    if (entry.includes('/')) {
      if (!ip) continue;
      const [address, prefix] = entry.split('/');
      const family = isIP(address);
      if (!family || !/^\d+$/.test(prefix)) continue;
      try {
        const block = new BlockList();
        block.addSubnet(address, Number(prefix), family === 6 ? 'ipv6' : 'ipv4');
        if (block.check(host, ip === 6 ? 'ipv6' : 'ipv4')) return true;
      } catch { /* Malformed bypass entries never disable the proxy. */ }
      continue;
    }
    entry = entry.replace(/^\*?\./, '');
    if (host === entry || (!ip && host.endsWith('.' + entry))) return true;
  }
  return false;
}

/** Selects the CONNECT proxy for a target from the process environment. Loopback
 * targets and NO_PROXY matches connect directly. */
export function proxyFor(target: URL, env: Environment = process.env): URL | undefined {
  if (isLoopback(target.hostname)) return undefined;
  const names = target.protocol === 'https:' ? ['HTTPS_PROXY', 'https_proxy'] : ['HTTP_PROXY', 'http_proxy'];
  const value = names.map(name => env[name]).find(candidate => candidate !== undefined && candidate !== '');
  if (value === undefined) return undefined;
  const bypass = env.NO_PROXY ?? env.no_proxy;
  if (bypass && bypassed(target, bypass)) return undefined;
  return parseProxyUrl(value);
}

function authority(host: string, port: number): string {
  return `${isIP(bare(host)) === 6 ? `[${bare(host)}]` : host}:${port}`;
}

/** Opens a TCP tunnel through an HTTP proxy. Resolves with the raw socket once
 * the proxy answers 2xx; the caller layers TLS on top for https targets. */
export function connectViaProxy(proxy: URL, host: string, port: number, signal?: AbortSignal): Promise<Socket> {
  return new Promise((resolve, reject) => {
    if (/[\s:/]/.test(bare(host)) && isIP(bare(host)) !== 6) { reject(new Error('invalid host')); return; }
    const socket = createConnection({ host: bare(proxy.hostname), port: proxyPort(proxy) });
    let head = '';
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      socket.off('data', onData); socket.off('error', onError); socket.off('close', onClose);
      signal?.removeEventListener('abort', onAbort);
      if (error) { socket.destroy(); reject(error); } else resolve(socket);
    };
    const onError = (): void => finish(new Error('proxy connection failed'));
    const onClose = (): void => finish(new Error('proxy closed the connection'));
    const onAbort = (): void => finish(new Error('aborted'));
    const onData = (chunk: Buffer): void => {
      head += chunk.toString('latin1');
      if (head.length > HEAD_LIMIT) { finish(new Error('proxy response too large')); return; }
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      const status = /^HTTP\/1\.[01] (\d{3})[ \r]/.exec(head);
      if (!status || status[1][0] !== '2') { finish(new Error('proxy refused the tunnel')); return; }
      const rest = head.slice(end + 4);
      if (rest) socket.unshift(Buffer.from(rest, 'latin1'));
      finish();
    };
    if (signal?.aborted) { onAbort(); return; }
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.on('data', onData); socket.once('error', onError); socket.once('close', onClose);
    socket.once('connect', () => {
      const target = authority(host, port);
      let credentials = '';
      if (proxy.username) {
        const pair = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
        credentials = `Proxy-Authorization: Basic ${Buffer.from(pair, 'utf8').toString('base64')}\r\n`;
      }
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${credentials}Connection: keep-alive\r\n\r\n`);
    });
  });
}

export interface Forwarder {
  port?: number;
  socketPath?: string;
  close(): Promise<void>;
}

/** A byte pipe from a local listener to the proxy. It parses nothing; the
 * sandboxed client speaks HTTP CONNECT to the real proxy through it. */
export async function startProxyForwarder(proxy: URL, listen: { socketPath: string } | { loopback: true }): Promise<Forwarder> {
  const active = new Set<Socket>();
  const server = createServer(client => {
    const upstream = createConnection({ host: bare(proxy.hostname), port: proxyPort(proxy) });
    active.add(client); active.add(upstream);
    const drop = (): void => { client.destroy(); upstream.destroy(); active.delete(client); active.delete(upstream); };
    client.on('error', drop); upstream.on('error', drop);
    client.on('close', drop); upstream.on('close', drop);
    client.pipe(upstream).pipe(client);
  });
  server.maxConnections = 64;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    const ready = (): void => { server.off('error', reject); resolve(); };
    if ('socketPath' in listen) server.listen(listen.socketPath, ready);
    else server.listen(0, '127.0.0.1', ready);
  });
  if ('socketPath' in listen) await chmod(listen.socketPath, 0o600);
  const address = server.address();
  return {
    port: address && typeof address === 'object' ? address.port : undefined,
    socketPath: 'socketPath' in listen ? listen.socketPath : undefined,
    async close(): Promise<void> {
      for (const socket of active) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

/** The proxy a sandboxed client may use: HTTPS_PROXY first, then HTTP_PROXY. */
export function proxyFromEnvironment(env: Environment = process.env): URL | undefined {
  const value = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'].map(name => env[name]).find(candidate => candidate);
  return value ? parseProxyUrl(value) : undefined;
}
