import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, stat, symlink, writeFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { configDirectory, endpointFor, makeConfig, initialize, loadConfig, loadKey, validateConfig } from '../src/config.js';
import { temporary } from './helpers.js';

const options = { baseUrl: 'http://127.0.0.1:1234/v1', model: 'synthetic-detector' };

test('URL validation allows HTTPS and only loopback HTTP; appends endpoint under base path', () => {
  for (const url of ['https://trusted.example/api/v1', 'http://localhost:8000/v1/', 'http://127.0.0.2:8000', 'http://[::1]:8000/v1']) {
    assert.ok(endpointFor(url).pathname.endsWith('/chat/completions'));
  }
  assert.equal(endpointFor('https://trusted.example/api/v1/').href, 'https://trusted.example/api/v1/chat/completions');
  for (const url of ['http://trusted.example/v1', 'http://localhost.example/v1', 'http://192.168.1.2/v1',
    'ftp://localhost/v1', 'https://user:secret@example.test/v1', 'https://example.test/?key=secret',
    'https://example.test/#secret', 'invalid']) assert.throws(() => endpointFor(url));
});

test('configuration rejects invalid fields and supports local config directory precedence', () => {
  assert.equal(configDirectory({ SEALGATE_CONFIG_DIR: '/private/sealgate', XDG_CONFIG_HOME: '/xdg' }), '/private/sealgate');
  assert.equal(configDirectory({ XDG_CONFIG_HOME: '/xdg' }), '/xdg/sealgate');
  assert.throws(() => configDirectory({ SEALGATE_CONFIG_DIR: 'relative' }));
  const config = makeConfig(options);
  for (const change of [{ version: 2 }, { model: '' }, { timeoutMs: 0 }, { timeoutMs: 300001 },
    { timeoutMs: 1.5 }, { apiKeyEnv: 'a-b' }, { apiKey: 'must-not-be-here' },
    { detectionInstructions: '' }, { additionalCategories: [''] }, { additionalCategories: 'secrets' }]) {
    assert.throws(() => validateConfig({ ...config, ...change }));
  }
  assert.equal(makeConfig({ ...options, apiKeyEnv: null }).apiKeyEnv, null);
});

test('initialization stores private key and config and never overwrites a key', async t => {
  const parent = await temporary(t);
  const dir = path.join(parent, 'config');
  await initialize(dir, options);
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
  for (const file of ['key', 'config.json']) assert.equal((await stat(path.join(dir, file))).mode & 0o777, 0o600);
  const key = await loadKey(dir);
  assert.equal(key.length, 32);
  assert.equal((await loadConfig(dir)).model, options.model);
  assert.ok(!(await readFile(path.join(dir, 'config.json'), 'utf8')).includes(key.toString('base64')));
  await assert.rejects(initialize(dir, options), /Already initialized/);
  assert.deepEqual(await loadKey(dir), key);
  await unlink(path.join(dir, 'config.json'));
  await initialize(dir, options);
  assert.deepEqual(await loadKey(dir), key);
});

test('key storage inside repositories or reached through symlinked parents is rejected', async t => {
  const parent = await temporary(t);
  const repo = path.join(parent, 'repo');
  await mkdir(repo);
  await mkdir(path.join(repo, '.git'));
  await assert.rejects(initialize(path.join(repo, 'nested', 'sealgate'), options), /outside a Git repository/);
  const alias = path.join(parent, 'alias');
  await symlink(repo, alias);
  await assert.rejects(initialize(path.join(alias, 'sealgate'), options), /outside a Git repository/);
});

test('unsafe modes, symlinks, bad key lengths and malformed config fail closed', async t => {
  const dir = await temporary(t);
  await initialize(dir, options);
  const keyPath = path.join(dir, 'key');
  await chmod(keyPath, 0o644);
  await assert.rejects(loadKey(dir), /mode 600/);
  await chmod(keyPath, 0o600);
  await writeFile(keyPath, 'bad key');
  await assert.rejects(loadKey(dir), /32 bytes/);
  await unlink(keyPath);
  const target = path.join(dir, 'target');
  await writeFile(target, Buffer.alloc(32), { mode: 0o600 });
  await symlink(target, keyPath);
  await assert.rejects(loadKey(dir));
  const configPath = path.join(dir, 'config.json');
  await writeFile(configPath, '{ malformed synthetic secret');
  await assert.rejects(loadConfig(dir), /Cannot read configuration/);
  await chmod(dir, 0o755);
  await assert.rejects(loadKey(dir), /mode 700/);
});
