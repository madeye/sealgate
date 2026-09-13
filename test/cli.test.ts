import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { initialize } from '../src/config.js';
import { encryptSpan } from '../src/crypto.js';
import { answer, cli, compiledRoot, provider, requestBody, root, temporary } from './helpers.js';
import type { CliResult } from './helpers.js';

test('CLI smoke: init, protect multiline UTF-8 stdin, and local decrypt preserve exact input', async t => {
  let calls = 0;
  let original;
  const baseUrl = await provider(t, async (req, res) => {
    calls++;
    original = (await requestBody(req)).messages[1].content;
    answer(res, { sensitive_substrings: ['sample@example.test', '秘密\n123-45-6789'] });
  });
  const dir = await temporary(t);
  const initialized = await cli(['init', '--base-url', baseUrl, '--model', 'synthetic-detector', '--api-key-env', 'SEALGATE_TEST_API_KEY'], '', dir);
  assert.equal(initialized.code, 0, initialized.stderr);
  assert.equal(initialized.stdout, '');
  const input = '\uFEFFDraft a message to sample@example.test.\r\n秘密\n123-45-6789\nAgain sample@example.test.';
  const protectedResult = await cli(['protect'], input, dir);
  assert.equal(protectedResult.code, 0, protectedResult.stderr);
  assert.equal(protectedResult.stderr, '');
  assert.equal(original, input);
  assert.ok(!protectedResult.stdout.includes('sample@example.test'));
  assert.ok(!protectedResult.stdout.includes('123-45-6789'));
  assert.equal(protectedResult.stdout.match(/\[\[SEALGATE:v1:/g)?.length, 3);
  // Offline decryption depends only on the key, even when provider config is absent.
  await unlink(path.join(dir, 'config.json'));
  const decrypted = await cli(['decrypt'], protectedResult.stdout, dir, { SEALGATE_TEST_API_KEY: '' });
  assert.equal(decrypted.code, 0, decrypted.stderr);
  assert.equal(decrypted.stdout, input);
  assert.equal(decrypted.stderr, '');
  assert.equal(calls, 1);
});

test('CLI no-match output is unchanged, with no added newline', async t => {
  const dir = await temporary(t);
  const baseUrl = await provider(t, (req, res) => answer(res, { sensitive_substrings: [] }));
  await initialize(dir, { baseUrl, model: 'test', apiKeyEnv: null });
  for (const input of ['public text', '\npublic text\r\n', '']) {
    const result = await cli(['protect'], input, dir);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout, input);
  }
});

test('CLI failures produce no prompt and never echo input, API keys, or response bodies', async t => {
  const dir = await temporary(t);
  let mode = 'invalid';
  const baseUrl = await provider(t, (req, res) => {
    if (mode === 'http') { res.writeHead(401); res.end('synthetic-input-secret synthetic-provider-key'); }
    else if (mode === 'malformed') res.end('synthetic-input-secret');
    else if (mode === 'timeout') { res.writeHead(200); res.write('{'); }
    else answer(res, { sensitive_substrings: ['synthetic-input-secret', 'not present'] });
  });
  await initialize(dir, { baseUrl, model: 'test', apiKeyEnv: 'SEALGATE_TEST_API_KEY', timeoutMs: 150 });
  const check = (result: CliResult): void => {
    assert.notEqual(result.code, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^sealgate: /);
    assert.ok(!result.stderr.includes('synthetic-input-secret'));
    assert.ok(!result.stderr.includes('synthetic-provider-key'));
  };
  for (mode of ['invalid', 'http', 'malformed', 'timeout']) check(await cli(['protect'], 'synthetic-input-secret', dir));
  check(await cli(['protect'], 'synthetic-input-secret', dir, { SEALGATE_TEST_API_KEY: '' }));
  check(await cli(['protect', 'synthetic-input-secret'], '', dir));
  check(await cli(['init', '--synthetic-input-secret'], '', dir));
  check(await cli(['protect'], Buffer.from([0xc3, 0x28]), dir));
  check(await cli(['protect'], 'x'.repeat(1024 * 1024 + 1), dir));
  check(await cli(['protect'], '[[SEALGATE:v1:existing]]', dir));
  await writeFile(path.join(dir, 'key'), 'bad key');
  check(await cli(['protect'], 'synthetic-input-secret', dir));
});

test('CLI decrypt buffers all markers before exposing any plaintext', async t => {
  const dir = await temporary(t);
  await initialize(dir, { baseUrl: 'http://localhost:1234/v1', model: 'test' });
  const key = await readFile(path.join(dir, 'key'));
  const valid = encryptSpan('synthetic-input-secret', key);
  for (const suffix of ['[[SEALGATE:v1:bad]]', '[[SEALGATE:v2:bad]]', '[[SEALGATE:', encryptSpan('other secret', randomBytes(32))]) {
    const result = await cli(['decrypt'], `${valid} then ${suffix}`, dir);
    assert.notEqual(result.code, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^sealgate: /);
    assert.ok(!result.stderr.includes('synthetic-input-secret'));
  }
});

test('plugin hook provides workflow context without accessing storage or exposing a tool', async () => {
  const manifest = JSON.parse(await readFile(path.join(root, '.claude-plugin/plugin.json'), 'utf8'));
  const hooks = JSON.parse(await readFile(path.join(root, 'hooks/hooks.json'), 'utf8'));
  assert.equal(manifest.name, 'sealgate');
  assert.equal(manifest.mcpServers, undefined);
  assert.deepEqual(Object.keys(hooks.hooks), ['SessionStart']);
  const hook = hooks.hooks.SessionStart[0].hooks[0];
  assert.equal(hook.command, 'node "${CLAUDE_PLUGIN_ROOT}/dist/scripts/session-start.js"');
  const { stdout, stderr } = await promisify(execFile)(process.execPath, [path.join(compiledRoot, 'scripts/session-start.js')], {
    env: { ...process.env, SEALGATE_CONFIG_DIR: '/does/not/exist' },
  });
  assert.equal(stderr, '');
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.hookEventName, 'SessionStart');
  assert.match(output.systemMessage, /separate local terminal/);
  assert.match(output.hookSpecificOutput.additionalContext, /Do not read SEALGATE keys/);
});
