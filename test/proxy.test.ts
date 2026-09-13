import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import { connect, createServer as createTcpServer } from 'node:net';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import path from 'node:path';
import { SealgateError } from '../src/errors.js';
import { proxyFor, parseProxyUrl, connectViaProxy, startProxyForwarder } from '../src/proxy.js';
import { request } from '../src/http.js';
import { ProviderNetworkPolicy } from '../src/provider-network.js';
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

test('guarded tool proxy blocks provider CONNECT destinations before the host proxy sees them', async t => {
  const target = new URL(await provider(t, (_req, res) => res.end('tool response')));
  const proxy = await mockProxy(t, (_host, port) => ({ host: '127.0.0.1', port }));
  const policy = new ProviderNetworkPolicy(async () => ['192.0.2.10', '2001:db8::10']);
  await policy.refresh();
  const forwarder = await startProxyForwarder(new URL(proxy.url), { loopback: true }, host => policy.blocks(host));
  t.after(() => forwarder.close());
  const url = new URL(`http://127.0.0.1:${forwarder.port}`);
  for (const host of ['api.anthropic.com', 'API.ANTHROPIC.COM.', '192.0.2.10', '2001:db8::10', '::ffff:192.0.2.10']) {
    await assert.rejects(connectViaProxy(url, host, 443), /refused/);
  }
  assert.deepEqual(proxy.log, []);
  const socket = await connectViaProxy(url, '127.0.0.1', Number(target.port));
  socket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  let body = ''; for await (const chunk of socket) body += chunk;
  assert.match(body, /tool response$/);
  assert.deepEqual(proxy.log, [`127.0.0.1:${target.port}`]);
});

test('guarded tool proxy checks HTTP destinations and reconstructs conflicting Host headers', async t => {
  const received: Array<{ url: string | undefined; host: string | undefined }> = [];
  const proxy = new URL(await provider(t, (req, res) => {
    received.push({ url: req.url, host: req.headers.host }); res.end('tool HTTP');
  }));
  const policy = new ProviderNetworkPolicy(async () => ['192.0.2.10']);
  await policy.refresh();
  const forwarder = await startProxyForwarder(proxy, { loopback: true }, host => policy.blocks(host));
  t.after(() => forwarder.close());
  const send = (target: string, host: string) => new Promise<string>((resolve, reject) => {
    const socket = connect(forwarder.port!, '127.0.0.1'); let response = '';
    socket.setTimeout(5000, () => socket.destroy(Error('proxy timeout')));
    socket.on('connect', () => socket.write(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
    socket.on('data', chunk => response += chunk); socket.on('end', () => resolve(response)); socket.on('error', reject);
  });
  for (const target of ['http://api.anthropic.com/v1/messages', 'http://192.0.2.10/v1/messages',
    'http://0xc000020a/v1/messages', 'http://[::ffff:192.0.2.10]/v1/messages', '/v1/messages']) {
    assert.match(await send(target, '127.0.0.1'), /^HTTP\/1\.1 403/);
  }
  assert.deepEqual(received, []);
  assert.match(await send('http://127.0.0.1:4321/tool', 'api.anthropic.com'), /tool HTTP$/);
  assert.deepEqual(received, [{ url: 'http://127.0.0.1:4321/tool', host: '127.0.0.1:4321' }]);
});

test('cancellation after CONNECT closes a stalled TLS handshake and rejects promptly', { timeout: 5000 }, async t => {
  let ready!: () => void;
  const clientHello = new Promise<void>(resolve => { ready = resolve; });
  const sockets = new Set<import('node:net').Socket>();
  const proxy = createTcpServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      socket.once('data', ready);
    });
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => proxy.close(() => resolve())); });
  const controller = new AbortController();
  t.after(() => controller.abort());
  const pending = request(new URL('https://upstream.test/'), { method: 'POST', headers: {}, body: 'synthetic',
    signal: controller.signal, env: { HTTPS_PROXY: `http://127.0.0.1:${(proxy.address() as { port: number }).port}` } });
  await clientHello;
  const rejected = assert.rejects(pending, /abort/i);
  const closed = once([...sockets][0], 'close');
  controller.abort();
  await rejected; await closed;
  assert.equal(sockets.size, 0);
});

test('malformed proxy credentials reject before opening a socket', async () => {
  for (const credentials of ['user:%', '%:password', 'user:%80', 'user:%E0%A4']) {
    const url = `http://${credentials}@127.0.0.1:1`;
    assert.throws(() => parseProxyUrl(url), /invalid URL encoding/);
    await assert.rejects(connectViaProxy(new URL(url), 'upstream.test', 443), /invalid URL encoding/);
    await assert.rejects(startProxyForwarder(new URL(url), { loopback: true }), /invalid URL encoding/);
  }
});

test('tool forwarding injects host proxy credentials for CONNECT and chunked HTTP', { timeout: 5000 }, async t => {
  const expected = `Basic ${Buffer.from('synthetic:p:ass').toString('base64')}`;
  const seen: Array<{ auth: string | undefined; body: string }> = [];
  const proxy = createHttpServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    seen.push({ auth: req.headers['proxy-authorization'], body });
    res.writeHead(req.headers['proxy-authorization'] === expected ? 200 : 407); res.end('http-ok');
  });
  proxy.on('connect', (req, socket) => {
    seen.push({ auth: req.headers['proxy-authorization'], body: 'CONNECT' });
    socket.end(req.headers['proxy-authorization'] === expected ? 'HTTP/1.1 200 OK\r\n\r\n' : 'HTTP/1.1 407 Authentication Required\r\n\r\n');
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => proxy.close(() => resolve())));
  const forwarder = await startProxyForwarder(new URL(`http://synthetic:p%3Aass@127.0.0.1:${(proxy.address() as { port: number }).port}`), { loopback: true });
  t.after(() => forwarder.close());
  const socket = await connectViaProxy(new URL(`http://127.0.0.1:${forwarder.port}`), 'upstream.test', 443);
  socket.destroy();
  await new Promise<void>((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port: forwarder.port, method: 'POST', path: 'http://upstream.test/tool',
      headers: { 'proxy-authorization': 'Basic client-supplied', 'transfer-encoding': 'chunked' } }, res => {
      assert.equal(res.statusCode, 200); res.resume(); res.on('end', resolve);
    });
    req.on('error', reject); req.write('chunk-'); req.end('body');
  });
  assert.deepEqual(seen, [{ auth: expected, body: 'CONNECT' }, { auth: expected, body: 'chunk-body' }]);
});
