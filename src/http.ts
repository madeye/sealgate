import { request as httpRequest } from 'node:http';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import type { Duplex } from 'node:stream';
import { connectViaProxy, proxyFor } from './proxy.js';
import type { Environment } from './types.js';

export interface HttpResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: IncomingMessage;
}

export interface RequestOptions {
  method: 'POST';
  headers: Record<string, string>;
  body: string | Buffer;
  signal?: AbortSignal;
  /** Environment consulted for HTTP(S)_PROXY and NO_PROXY. */
  env?: Environment;
  /** Library/test injection only: extra trust anchors for the upstream TLS session. */
  ca?: string;
}

/** Sends one request without redirects or content decoding. Honors proxy
 * environment variables through a CONNECT tunnel; loopback targets connect directly. */
export function request(url: URL, options: RequestOptions): Promise<HttpResponse> {
  const secure = url.protocol === 'https:';
  const proxy = proxyFor(url, options.env);
  const port = Number(url.port) || (secure ? 443 : 80);
  const headers = { 'accept-encoding': 'identity', ...options.headers };
  return new Promise((resolve, reject) => {
    const base = { method: options.method, headers, signal: options.signal, ...(options.ca ? { ca: options.ca } : {}) };
    const tunnel = proxy ? {
      agent: undefined,
      createConnection(_options: unknown, callback: (error: Error | null, socket: Duplex) => void): undefined {
        const failed = (error: unknown): void => callback(error instanceof Error ? error : new Error('proxy failure'), undefined as never);
        connectViaProxy(proxy, url.hostname, port, options.signal).then(socket => {
          if (!secure) { callback(null, socket); return; }
          const tls = tlsConnect({ socket, servername: url.hostname, host: url.hostname, port, ...(options.ca ? { ca: options.ca } : {}) });
          tls.once('error', failed);
          tls.once('secureConnect', () => { tls.off('error', failed); callback(null, tls); });
        }, failed);
        return undefined;
      },
    } : {};
    const req = (secure ? httpsRequest : httpRequest)(url, { ...base, ...tunnel }, response => {
      resolve({ status: response.statusCode ?? 0, headers: response.headers, body: response });
    });
    req.once('error', reject);
    req.end(options.body);
  });
}
