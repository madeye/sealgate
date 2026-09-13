import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { RequestProtector } from '../src/request-protection.js';
import { startGateway } from '../src/gateway.js';
import { decryptText } from '../src/crypto.js';
import { provider, answer } from './helpers.js';
import { makeConfig } from '../src/config.js';
import { detectSensitive } from '../src/provider.js';
import type { TestContext } from 'node:test';
import type { IncomingHttpHeaders } from 'node:http';

const AUTH = 'Bearer synthetic-subscription-token';
const BETA = 'oauth-2025-04-20,interleaved-thinking-2025-05-14';
const HEADERS = { authorization: AUTH, 'anthropic-version': '2023-06-01', 'anthropic-beta': BETA, 'content-type': 'application/json' };
const request = (text = 'Hello') => ({ model: 'claude-test', max_tokens: 1024, messages: [{ role: 'user', content: text }] });

function restore(value: unknown, key: Buffer): unknown {
  if (typeof value === 'string') return decryptText(value, key);
  if (Array.isArray(value)) return value.map(child => restore(child, key));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([name, child]) => [name, restore(child, key)]));
  return value;
}

async function harness(t: TestContext, secrets: string[] = [], timeoutMs = 2000) {
  const captured: Array<{ body: string; headers: IncomingHttpHeaders; url: string }> = [];
  const detectorInputs: string[] = [];
  const detectorUrl = await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    const data = JSON.parse(Buffer.concat(chunks).toString());
    detectorInputs.push(data.messages[1].content);
    assert.equal(req.headers.authorization, 'Bearer synthetic-local-vllm-key');
    answer(res, { sensitive_substrings: secrets.filter(secret => data.messages[1].content.includes(secret)) });
  });
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    captured.push({ body: Buffer.concat(chunks).toString(), headers: req.headers, url: req.url! });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ content: [{ type: 'text', text: 'Synthetic reply' }] }));
  })).replace(/\/v1$/, '');
  const key = randomBytes(32);
  const config = makeConfig({ baseUrl: detectorUrl, model: 'local-vllm', apiKeyEnv: 'LOCAL_KEY' });
  const protector = new RequestProtector(key, (text, signal) => detectSensitive(text, config, { LOCAL_KEY: 'synthetic-local-vllm-key' }, signal));
  const gateway = await startGateway({ protector, authorization: AUTH, upstream, timeoutMs });
  t.after(() => gateway.close());
  assert.ok(gateway.address && typeof gateway.address !== 'string');
  const url = `http://127.0.0.1:${gateway.address.port}`;
  return { captured, detectorInputs, key, protector, url,
    send: (body: unknown, route = '/v1/messages?beta=true', headers = HEADERS) => fetch(url + route, { method: 'POST', headers, body: JSON.stringify(body) }) };
}

test('complete request encryption: system, history, Unicode, tools, schema, metadata, multiline and repeated text', async t => {
  const secret = 'alice@example.test'; const confidential = '機密\nproject α';
  const h = await harness(t, [secret, confidential]);
  const body = { ...request(),
    system: [{ type: 'text', text: `Contact ${secret}. ${confidential}`, cache_control: { type: 'ephemeral' } }],
    messages: [
      { role: 'user', content: `First ${secret}; again ${secret}.` },
      { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_123', name: 'Read', input: { path: `/data/${secret}`, nested: [{ note: confidential }] } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_123', content: [{ type: 'text', text: `File says ${secret}\n${confidential}` }] }] },
    ],
    tools: [{ name: 'Read', description: `For ${secret}`, input_schema: { type: 'object', properties: { path: { type: 'string', description: confidential, enum: [secret] } } } }],
    metadata: { user_id: `Contact ${secret}` },
  };
  const response = await h.send(body); assert.equal(response.status, 200);
  const sent = h.captured[0];
  for (const value of [secret, confidential, 'synthetic-local-vllm-key']) assert.ok(!sent.body.includes(value));
  assert.deepEqual(restore(JSON.parse(sent.body), h.key), body);
  assert.equal(sent.headers.authorization, AUTH); assert.equal(sent.headers['anthropic-beta'], BETA);
  assert.equal(sent.headers['anthropic-version'], HEADERS['anthropic-version']);
  assert.equal(sent.url, '/v1/messages?beta=true');
  assert.ok(h.detectorInputs[0].includes(confidential));
  assert.ok(!h.detectorInputs[0].includes(AUTH));
  const markers = sent.body.match(/\[\[SEALGATE:v1:[A-Za-z0-9_-]+\]\]/g)!;
  assert.equal(new Set(markers).size, 2, 'same spans use stable session ciphertext');
});

test('no matches preserve data; overlapping matches merge; repeated history and issued ciphertext can be replayed', async () => {
  const key = randomBytes(32);
  const protector = new RequestProtector(key, async text => ({ sensitive_substrings: ['aba', 'bab'].filter(s => text.includes(s)) }));
  const body = request('Keep ababa here.');
  const first = await protector.protect(body);
  assert.deepEqual(restore(JSON.parse(first.body), key), body);
  assert.equal((first.body.match(/\[\[SEALGATE:/g) ?? []).length, 1);
  assert.equal((await protector.protect(body)).body, first.body);
  assert.equal((await protector.protect(JSON.parse(first.body))).body, first.body);
  assert.deepEqual(JSON.parse((await protector.protect(request())).body), request());
  await assert.rejects(protector.protect(request('Unknown [[SEALGATE:v1:fake]]')), /unknown or modified/);
});

test('secrets in JSON keys, numeric values, protocol fields and headers block the whole request', async t => {
  for (const [body, secret] of [[request(), 'claude-test'], [request(), '1024'], [{ ...request(), metadata: { secretkey: 'value' } }, 'secretkey']] as const) {
    const h = await harness(t, [secret]);
    assert.equal((await h.send(body)).status, 400); assert.equal(h.captured.length, 0);
  }
  const h = await harness(t, ['interleaved-thinking-2025-05-14']);
  assert.equal((await h.send(request())).status, 400); assert.equal(h.captured.length, 0);
});

test('opaque uploads, new endpoints, unknown fields, bad auth and compressed bodies never reach upstream', async t => {
  const h = await harness(t);
  for (const body of [
    { ...request(), extra_future_field: 'secret' },
    { ...request(), messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', data: 'c2VjcmV0' } }] }] },
    { ...request(), messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'url', url: 'https://example.test/secret' } }] }] },
  ]) assert.equal((await h.send(body)).status, 400);
  for (const route of ['/v1/messages?secret=raw', '/v1/messages?beta=true&extra=raw', '/v1/files', '/v1/models', '/telemetry']) {
    assert.equal((await h.send(request(), route)).status, 403);
  }
  assert.equal((await h.send(request(), '/v1/messages', { ...HEADERS, authorization: 'Bearer wrong' })).status, 401);
  assert.equal((await h.send(request(), '/v1/messages', { ...HEADERS, 'x-api-key': 'wrong' } as typeof HEADERS)).status, 401);
  assert.equal((await h.send(request(), '/v1/messages', { ...HEADERS, 'content-encoding': 'gzip' } as typeof HEADERS)).status, 415);
  assert.equal(h.captured.length, 0);
});

test('token counting is protected and unneeded client headers are consumed locally', async t => {
  const h = await harness(t, ['token-count-secret']);
  assert.equal((await h.send(request('token-count-secret'), '/v1/messages/count_tokens', {
    ...HEADERS, 'x-custom-secret': 'header-secret', 'user-agent': 'private-machine-name',
  } as typeof HEADERS)).status, 200);
  assert.ok(!h.captured[0].body.includes('token-count-secret'));
  assert.equal(h.captured[0].headers['x-custom-secret'], undefined);
  assert.equal(h.captured[0].headers['user-agent'], 'sealgate/0.4.0');
});

test('malformed detector results, cross-field matches, encryption errors and cancellation fail closed', async t => {
  const upstreamCalls: number[] = [];
  const upstream = (await provider(t, (_req, res) => { upstreamCalls.push(1); res.end(); })).replace(/\/v1$/, '');
  for (const [key, detect] of [
    [randomBytes(32), async () => ({ sensitive_substrings: ['not in input'] })],
    [randomBytes(32), async () => ({ unexpected: [] })],
    [randomBytes(32), async (text: string) => ({ sensitive_substrings: [text] })],
    [Buffer.alloc(1), async () => ({ sensitive_substrings: ['Hello'] })],
    [randomBytes(32), async () => { throw new Error('private-provider-response-must-not-leak'); }],
  ] as const) {
    const gateway = await startGateway({ protector: new RequestProtector(key, detect), authorization: AUTH, upstream });
    t.after(() => gateway.close()); assert.ok(gateway.address && typeof gateway.address !== 'string');
    const response = await fetch(`http://127.0.0.1:${gateway.address.port}/v1/messages`, { method: 'POST', headers: HEADERS, body: JSON.stringify(request()) });
    assert.ok(response.status >= 400); assert.ok(!(await response.text()).includes('private-provider-response'));
  }
  assert.equal(upstreamCalls.length, 0);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(new RequestProtector(randomBytes(32), async () => ({ sensitive_substrings: [] })).protect(request(), [], controller.signal), /canceled/);
});

test('signed blocks must match a remote block exactly, including redacted thinking', async () => {
  const protector = new RequestProtector(randomBytes(32), async text => ({ sensitive_substrings: text.includes('cache-secret') ? ['cache-secret'] : [] }));
  for (const block of [{ type: 'thinking', thinking: 'Remote thoughts', signature: 'opaque-signature' }, { type: 'redacted_thinking', data: 'opaque-remote-data' }]) {
    const body = { ...request(), messages: [{ role: 'assistant', content: [block] }] };
    await assert.rejects(protector.protect(body), /signed content/);
    protector.rememberRemoteBlock(block);
    assert.deepEqual(JSON.parse((await protector.protect(body)).body), body);
    await assert.rejects(protector.protect({ ...body, messages: [{ role: 'assistant', content: [{ ...block, injected: { secret: 'raw' } }] }] }), /signed content/);
    await assert.rejects(protector.protect({ ...body, messages: [{ role: 'assistant', content: [{ ...block, cache_control: { type: 'cache-secret' } }] }] }), /sensitive protocol/);
  }
});

test('SSE streams immediately and unchanged, and only completed upstream signed blocks can be replayed', async t => {
  let release!: () => void;
  const released = new Promise<void>(resolve => { release = resolve; });
  const events = [
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Remote"}}\n\n',
    ': ping\n\nevent: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signed"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
  ];
  const upstream = (await provider(t, async (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(events[0]);
    await released;
    for (const event of events.slice(1)) res.write(event);
    res.end();
  })).replace(/\/v1$/, '');
  t.after(release);
  const protector = new RequestProtector(randomBytes(32), async () => ({ sensitive_substrings: [] }));
  const gateway = await startGateway({ protector, upstream, authorization: AUTH });
  t.after(() => gateway.close()); assert.ok(gateway.address && typeof gateway.address !== 'string');
  const response = await fetch(`http://127.0.0.1:${gateway.address.port}/v1/messages`, { method: 'POST', headers: HEADERS, body: JSON.stringify(request()) });
  const reader = response.body!.getReader();
  const first = await reader.read(); assert.equal(Buffer.from(first.value!).toString(), events[0]);
  release();
  const chunks = [Buffer.from(first.value!)];
  while (true) { const chunk = await reader.read(); if (chunk.done) break; chunks.push(Buffer.from(chunk.value)); }
  assert.equal(Buffer.concat(chunks).toString(), events.join(''));
  const body = { ...request(), messages: [{ role: 'assistant', content: [{ type: 'thinking', thinking: 'Remote', signature: 'signed' }] }] };
  assert.deepEqual(JSON.parse((await protector.protect(body)).body), body);
});

test('upstream redirects are blocked and timeout cancels detection without a remote request', async t => {
  const h = await harness(t);
  const upstream = (await provider(t, (_req, res) => { res.writeHead(307, { location: h.url + '/leak' }); res.end(); })).replace(/\/v1$/, '');
  const gateway = await startGateway({ protector: h.protector, authorization: AUTH, upstream });
  t.after(() => gateway.close()); assert.ok(gateway.address && typeof gateway.address !== 'string');
  assert.equal((await fetch(`http://127.0.0.1:${gateway.address.port}/v1/messages`, { method: 'POST', headers: HEADERS, body: JSON.stringify(request()) })).status, 502);
  let aborted = false;
  const slow = new RequestProtector(randomBytes(32), (_text, signal) => new Promise((_resolve, reject) => {
    signal!.addEventListener('abort', () => { aborted = true; reject(new Error('canceled')); });
  }));
  const timeoutGateway = await startGateway({ protector: slow, authorization: AUTH, upstream, timeoutMs: 30 });
  t.after(() => timeoutGateway.close()); assert.ok(timeoutGateway.address && typeof timeoutGateway.address !== 'string');
  assert.equal((await fetch(`http://127.0.0.1:${timeoutGateway.address.port}/v1/messages`, { method: 'POST', headers: HEADERS, body: JSON.stringify(request()) })).status, 502);
  assert.ok(aborted); assert.equal(h.captured.length, 0);
});
