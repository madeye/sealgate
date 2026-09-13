import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import { connect } from 'node:net';
import path from 'node:path';
import { SealgateError } from '../src/errors.js';
import { proxyFor, parseProxyUrl, connectViaProxy, startProxyForwarder } from '../src/proxy.js';
import { request } from '../src/http.js';
import { provider, mockProxy, fixtures } from './helpers.js';
import type { TestContext } from 'node:test';

const anthropic = new URL('https://api.anthropic.com/v1/messages');

test('proxy selection follows the target scheme, bypasses loopback and honors NO_PROXY forms', () => {
  const env = { HTTPS_PROXY: 'http://127.0.0.1:8081', http_proxy: 'http://user:p%40ss@proxy.internal:3128',
    NO_PROXY: 'localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,*.local,.corp.example,exact.example:8443' };
  assert.equal(proxyFor(anthropic, env)?.href, 'http://127.0.0.1:8081/');
  assert.equal(proxyFor(new URL('http://example.com/'), env)?.href, 'http://user:p%40ss@proxy.internal:3128/');
  assert.equal(proxyFor(new URL('http://127.0.0.1:8000/v1'), env), undefined);
  assert.equal(proxyFor(new URL('https://localhost:9/'), env), undefined);
  assert.equal(proxyFor(new URL('https://[::1]/'), env), undefined);
  assert.equal(proxyFor(new URL('https://10.20.30.40/'), env), undefined);
  assert.equal(proxyFor(new URL('https://172.31.255.1/'), env), undefined);
  assert.equal(proxyFor(new URL('https://172.32.0.1/'), env)?.href, 'http://127.0.0.1:8081/');
  assert.equal(proxyFor(new URL('https://printer.local/'), env), undefined);
  assert.equal(proxyFor(new URL('https://git.corp.example/'), env), undefined);
  assert.equal(proxyFor(new URL('https://corp.example/'), env), undefined);
  assert.equal(proxyFor(new URL('https://notcorp.example/'), env)?.href, 'http://127.0.0.1:8081/');
  assert.equal(proxyFor(new URL('https://exact.example:8443/'), env), undefined);
  assert.equal(proxyFor(new URL('https://exact.example/'), env)?.href, 'http://127.0.0.1:8081/');
  assert.equal(proxyFor(anthropic, { ...env, NO_PROXY: '*' }), undefined);
  assert.equal(proxyFor(anthropic, { HTTPS_PROXY: '' }), undefined);
  assert.equal(proxyFor(anthropic, {}), undefined);
  for (const bad of ['https://proxy:3128', 'socks5://127.0.0.1:1080', 'http://127.0.0.1:8081/path', 'http://127.0.0.1:8081/?x=1', 'not a url', 'http://']) {
    assert.throws(() => proxyFor(anthropic, { HTTPS_PROXY: bad }), SealgateError);
    assert.throws(() => parseProxyUrl(bad), SealgateError);
  }
});

async function tlsUpstream(t: TestContext, onRequest: (body: string) => void): Promise<{ port: number; ca: string }> {
  const [key, cert] = await Promise.all([readFile(path.join(fixtures, 'tls/key.pem')), readFile(path.join(fixtures, 'tls/cert.pem'))]);
  const server = createHttpsServer({ key, cert }, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    onRequest(Buffer.concat(chunks).toString());
    res.setHeader('content-type', 'application/json'); res.end('{"ok":true}');
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); }));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected a TCP upstream.');
  return { port: address.port, ca: cert.toString() };
}

test('requests tunnel through a CONNECT proxy for plain HTTP and TLS, verifying the certificate name', async t => {
  const seen: string[] = [];
  const plainUrl = new URL(await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    seen.push(`plain:${req.headers.host}:${Buffer.concat(chunks)}`); res.end('plain-ok');
  }));
  const tls = await tlsUpstream(t, body => seen.push(`tls:${body}`));
  const proxy = await mockProxy(t, (host, port) => host === 'upstream.test' || host === 'other.test' ? { host: '127.0.0.1', port } : undefined);
  const env = { HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url.replace('http://127.0.0.1', 'http://alice:s%3Acret@127.0.0.1') };
  const plain = await request(new URL(`http://upstream.test:${plainUrl.port}/v1/chat/completions`), { method: 'POST', headers: {}, body: 'hello', env });
  assert.equal(plain.status, 200);
  let text = ''; for await (const chunk of plain.body) text += chunk; assert.equal(text, 'plain-ok');
  const secure = await request(new URL(`https://upstream.test:${tls.port}/v1/messages`), { method: 'POST', headers: {}, body: '{"a":1}', env, ca: tls.ca });
  assert.equal(secure.status, 200);
  text = ''; for await (const chunk of secure.body) text += chunk; assert.equal(text, '{"ok":true}');
  assert.deepEqual(proxy.log, [`upstream.test:${plainUrl.port}`, `upstream.test:${tls.port}`]);
  assert.deepEqual(proxy.authorizations, [undefined, `Basic ${Buffer.from('alice:s:cret').toString('base64')}`]);
  assert.deepEqual(seen, [`plain:upstream.test:${plainUrl.port}:hello`, 'tls:{"a":1}']);
  // A certificate for upstream.test must not satisfy another name reached through the same tunnel.
  await assert.rejects(request(new URL(`https://other.test:${tls.port}/`), { method: 'POST', headers: {}, body: '', env, ca: tls.ca }));
  // Without the trust anchor the self-signed upstream is rejected.
  await assert.rejects(request(new URL(`https://upstream.test:${tls.port}/`), { method: 'POST', headers: {}, body: '', env }));
  // A refused tunnel, a closed proxy port, and an aborted attempt all fail.
  await assert.rejects(request(new URL('https://refused.test:443/'), { method: 'POST', headers: {}, body: '', env }));
  await assert.rejects(connectViaProxy(new URL('http://127.0.0.1:1'), 'upstream.test', 443));
  await assert.rejects(connectViaProxy(new URL(proxy.url), 'upstream.test', tls.port, AbortSignal.abort()));
});

test('the forwarder pipes bytes to the proxy and stops when closed', async t => {
  const target = new URL(await provider(t, (_req, res) => res.end('through')));
  const proxy = await mockProxy(t, (host, port) => host === 'upstream.test' ? { host: '127.0.0.1', port } : undefined);
  const forwarder = await startProxyForwarder(new URL(proxy.url), { loopback: true });
  assert.ok(forwarder.port);
  const socket = await connectViaProxy(new URL(`http://127.0.0.1:${forwarder.port}`), 'upstream.test', Number(target.port));
  socket.write('GET / HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n');
  let response = ''; for await (const chunk of socket) response += chunk;
  assert.match(response, /\r\n\r\nthrough$/);
  assert.deepEqual(proxy.log, [`upstream.test:${target.port}`]);
  await forwarder.close();
  await assert.rejects(new Promise((resolve, reject) => {
    const attempt = connect({ host: '127.0.0.1', port: forwarder.port! }, () => resolve(undefined));
    attempt.on('error', reject);
  }));
});
