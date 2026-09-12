import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { makeConfig, initialize } from '../src/config.js';
import { providerSettings } from '../src/env.js';
import { answer, cli, provider, requestBody, temporary } from './helpers.js';

const config = makeConfig({ baseUrl: 'http://localhost:8000/v1', model: 'default' });

test('.env provider settings override config; exported settings override .env', async t => {
  const cwd = await temporary(t);
  await writeFile(path.join(cwd, '.env'), [
    'HECC_BASE_URL=http://127.0.0.1:8080/v1',
    'HECC_MODEL="local model"',
    'HECC_TIMEOUT_MS=120000',
    'HECC_ENABLE_THINKING=false',
    'HECC_API_KEY_ENV=LOCAL_TEST_TOKEN',
    'LOCAL_TEST_TOKEN="synthetic#credential"',
    'HECC_CONFIG_DIR=/must/not/move/key',
    'NODE_OPTIONS=--must-not-be-used',
  ].join('\n'), { mode: 0o600 });
  const settings = await providerSettings(config, { cwd, env: {} });
  assert.equal(settings.config.baseUrl, 'http://127.0.0.1:8080/v1');
  assert.equal(settings.config.model, 'local model');
  assert.equal(settings.config.timeoutMs, 120000);
  assert.equal(settings.config.enableThinking, false);
  assert.deepEqual(settings.env, { LOCAL_TEST_TOKEN: 'synthetic#credential' });
  assert.equal(Object.hasOwn(settings.config, 'HECC_CONFIG_DIR'), false);
  assert.equal(config.model, 'default');
  const exported = await providerSettings(config, { cwd, env: { HECC_MODEL: 'exported-model', LOCAL_TEST_TOKEN: 'exported-key', HECC_ENABLE_THINKING: 'true' } });
  assert.equal(exported.config.model, 'exported-model');
  assert.equal(exported.config.enableThinking, true);
  await assert.rejects(providerSettings(config, { cwd, env: { HECC_ENABLE_THINKING: 'no' } }), /true or false/);
  assert.equal(exported.env.LOCAL_TEST_TOKEN, 'exported-key');
});

test('missing .env preserves config and explicit empty API-key name disables auth', async t => {
  const cwd = await temporary(t);
  const settings = await providerSettings(config, { cwd, env: { HECC_API_KEY: 'synthetic-key' } });
  assert.deepEqual(settings.config, config);
  assert.equal(settings.env.HECC_API_KEY, 'synthetic-key');
  await writeFile(path.join(cwd, '.env'), 'HECC_API_KEY_ENV=\n', { mode: 0o600 });
  const noAuth = await providerSettings(config, { cwd, env: {} });
  assert.equal(noAuth.config.apiKeyEnv, null);
  assert.deepEqual(noAuth.env, {});
});

test('unsafe .env permissions, links, and invalid provider settings fail closed', async t => {
  const cwd = await temporary(t);
  const file = path.join(cwd, '.env');
  await writeFile(file, 'HECC_TIMEOUT_MS=invalid', { mode: 0o600 });
  await assert.rejects(providerSettings(config, { cwd, env: {} }), /Invalid configuration/);
  await writeFile(file, 'HECC_BASE_URL=http://remote.example/v1');
  await assert.rejects(providerSettings(config, { cwd, env: {} }), /HTTPS/);
  await chmod(file, 0o644);
  await assert.rejects(providerSettings(config, { cwd, env: {} }), /mode 600/);
  const linked = await temporary(t);
  await symlink(file, path.join(linked, '.env'));
  await assert.rejects(providerSettings(config, { cwd: linked, env: {} }), /Cannot read .env/);
});

test('CLI uses .env for detection and decrypt ignores even an invalid .env', async t => {
  const cwd = await temporary(t);
  let request: {
    body: Awaited<ReturnType<typeof requestBody>>;
    auth: string | undefined;
  } | undefined;
  const baseUrl = await provider(t, async (req, res) => {
    request = { body: await requestBody(req), auth: req.headers.authorization };
    answer(res, { sensitive_substrings: ['synthetic@example.test'] });
  });
  await initialize(cwd, { baseUrl: 'http://localhost:1/v1', model: 'wrong-model' });
  const file = path.join(cwd, '.env');
  await writeFile(file, `HECC_BASE_URL=${baseUrl}\nHECC_MODEL=dotenv-model\nHECC_API_KEY=synthetic-dotenv-key\n`, { mode: 0o600 });
  const original = 'Write to synthetic@example.test.\n';
  const result = await cli(['protect'], original, cwd);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(!result.stdout.includes('synthetic@example.test'));
  assert.ok(request);
  assert.equal(request.body.model, 'dotenv-model');
  assert.equal(request.auth, 'Bearer synthetic-dotenv-key');
  await writeFile(file, 'HECC_TIMEOUT_MS=invalid');
  const failed = await cli(['protect'], original, cwd);
  assert.notEqual(failed.code, 0);
  assert.equal(failed.stdout, '');
  const decrypted = await cli(['decrypt'], result.stdout, cwd);
  assert.equal(decrypted.code, 0, decrypted.stderr);
  assert.equal(decrypted.stdout, original);
});
