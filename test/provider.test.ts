import test from 'node:test';
import assert from 'node:assert/strict';
import type { IncomingHttpHeaders, RequestListener } from 'node:http';
import { detectSensitive } from '../src/provider.js';
import { makeConfig } from '../src/config.js';
import { answer, provider, requestBody } from './helpers.js';

test('provider receives configured model, instructions, auth and original prompt', async t => {
  let received: {
    url: string | undefined;
    method: string | undefined;
    headers: IncomingHttpHeaders;
    body: Awaited<ReturnType<typeof requestBody>>;
  } | undefined;
  const baseUrl = await provider(t, async (req, res) => {
    received = { url: req.url, method: req.method, headers: req.headers, body: await requestBody(req) };
    answer(res, { sensitive_substrings: ['synthetic secret'] });
  });
  const config = { ...makeConfig({ baseUrl, model: 'private-model', apiKeyEnv: 'PRIVATE_TOKEN' }),
    detectionInstructions: 'Custom detection rules.', additionalCategories: ['Internal project names'] };
  const prompt = 'hello\nsynthetic secret 🔐';
  assert.deepEqual(await detectSensitive(prompt, config, { PRIVATE_TOKEN: 'test-token' }), { sensitive_substrings: ['synthetic secret'] });
  assert.ok(received);
  assert.equal(received.url, '/v1/chat/completions');
  assert.equal(received.method, 'POST');
  assert.equal(received.headers.authorization, 'Bearer test-token');
  assert.equal(received.body.model, 'private-model');
  assert.equal(received.body.messages[1].content, prompt);
  assert.match(received.body.messages[0].content, /Custom detection rules/);
  assert.match(received.body.messages[0].content, /Internal project names/);
  assert.deepEqual(received.body.response_format, { type: 'json_object' });
  assert.equal(received.body.stream, false);
  assert.equal(received.body.chat_template_kwargs, undefined);
});

test('explicit Qwen/vLLM thinking configuration reaches the chat template', async t => {
  const baseUrl = await provider(t, async (req, res) => {
    assert.deepEqual((await requestBody(req)).chat_template_kwargs, { enable_thinking: false });
    answer(res, { sensitive_substrings: [] });
  });
  await detectSensitive('public', { ...makeConfig({ baseUrl, model: 'qwen', apiKeyEnv: null }), enableThinking: false });
});

test('missing API key fails before a request; explicit unauthenticated configuration works', async t => {
  let calls = 0;
  const baseUrl = await provider(t, (req, res) => {
    calls++;
    assert.equal(req.headers.authorization, undefined);
    answer(res, { sensitive_substrings: [] });
  });
  await assert.rejects(detectSensitive('public', makeConfig({ baseUrl, model: 'test' }), {}), /API-key/);
  assert.equal(calls, 0);
  await detectSensitive('public', makeConfig({ baseUrl, model: 'test', apiKeyEnv: null }));
  assert.equal(calls, 1);
});

test('provider timeout covers waiting for headers and a stalled response body', async t => {
  for (const bodyStarted of [false, true]) {
    const baseUrl = await provider(t, (req, res) => {
      if (bodyStarted) { res.writeHead(200); res.write('{'); }
    });
    const start = Date.now();
    await assert.rejects(detectSensitive('synthetic secret', makeConfig({ baseUrl, model: 'test', apiKeyEnv: null, timeoutMs: 75 })), /timed out/);
    assert.ok(Date.now() - start < 3000);
  }
});

test('redirects never forward plaintext or auth to another endpoint', async t => {
  let forwarded = false;
  const target = await provider(t, (req, res) => { forwarded = true; answer(res, { sensitive_substrings: [] }); });
  const baseUrl = await provider(t, (req, res) => {
    res.writeHead(307, { Location: `${target}/chat/completions` });
    res.end();
  });
  await assert.rejects(detectSensitive('synthetic secret', makeConfig({ baseUrl, model: 'test', apiKeyEnv: null })));
  assert.equal(forwarded, false);
});

test('HTTP errors, malformed JSON, truncated answers, refusals and oversized responses are rejected without body leakage', async t => {
  const handlers: RequestListener[] = [
    (req, res) => { res.writeHead(500); res.end('synthetic secret'); },
    (req, res) => res.end('synthetic secret'),
    (req, res) => answer(res, {}, { finish_reason: 'length' }),
    (req, res) => answer(res, {}, { message: { role: 'assistant', content: 'synthetic secret' } }),
    (req, res) => answer(res, {}, { message: { role: 'assistant', content: '{}', refusal: 'synthetic secret' } }),
    (req, res) => res.end(JSON.stringify({ choices: [] })),
    (req, res) => res.end('x'.repeat(4 * 1024 * 1024 + 1)),
  ];
  for (const handler of handlers) {
    const baseUrl = await provider(t, handler);
    await assert.rejects(detectSensitive('synthetic secret', makeConfig({ baseUrl, model: 'test', apiKeyEnv: null })), error => {
      assert.ok(error instanceof Error);
      assert.ok(!error.message.includes('synthetic secret'));
      return true;
    });
  }
});
