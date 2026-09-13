// Run after npm run build. All fixtures and HTTP services are local and synthetic.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, stat, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeConfig } from '../dist/src/config.js';
import { decryptText } from '../dist/src/crypto.js';
import { detectSensitive } from '../dist/src/provider.js';
import { RequestProtector } from '../dist/src/request-protection.js';
import { startGateway } from '../dist/src/gateway.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const temporary = await mkdtemp(path.join(tmpdir(), 'sealgate-verification-'));
const configDir = path.join(temporary, 'config');
// An allowlist and an empty working directory keep checkout .env and credentials out.
const env = { PATH: process.env.PATH, SEALGATE_CONFIG_DIR: configDir };
const services = [];
let gateway;
const secret = 'alice@example.test';
const multiline = '秘密\n123-45-6789';
let mode = 'valid';
const detections = [];
const forwarded = [];
const dump = (name, value) => console.log(`${name}: ${JSON.stringify(value)}`);
const step = title => console.log(`\n=== ${title} ===`);
const pass = message => console.log(`PASS: ${message}`);

async function listen(handler) {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch(error => res.destroy(error));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  services.push(server);
  return `http://127.0.0.1:${server.address().port}`;
}

async function body(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function command(args, input = '', script = 'dist/bin/sealgate.js') {
  dump('command argv', ['node', script, ...args]);
  dump('stdin', input);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, script), ...args], {
      cwd: temporary, env, stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout = []; const stderr = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.stdin.on('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString(), code, signal });
    });
    child.stdin.end(input);
  });
  dump('stdout', result.stdout); dump('stderr', result.stderr); dump('exit code', result.code);
  assert.equal(result.signal, null, 'command must not time out or receive a signal');
  return result;
}

function success(result) {
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, '');
}

try {
  console.log('SEALGATE tool verification — captured synthetic fixtures');
  dump('captured at', new Date().toISOString());
  dump('runtime', { node: process.version, platform: process.platform, arch: process.arch });
  console.log('Strings are JSON-encoded without truncation; \\n and \\r preserve exact line endings.');
  console.log('Ports and ciphertext change on every run. No key bytes are dumped.');

  const detector = await listen(async (req, res) => {
    const raw = await body(req);
    const parsed = JSON.parse(raw);
    const answer = { sensitive_substrings: mode === 'invalid' ? ['not present in the input'] :
      [secret, multiline].filter(value => parsed.messages[1].content.includes(value)) };
    const response = JSON.stringify({ choices: [{ finish_reason: 'stop', message: {
      role: 'assistant', content: JSON.stringify(answer),
    } }] });
    detections.push({ method: req.method, url: req.url, body: raw, response });
    res.setHeader('content-type', 'application/json'); res.end(response);
  });

  step('1. Initialize isolated storage');
  const initialized = await command(['init', '--base-url', `${detector}/v1`, '--model', 'synthetic-detector', '--no-api-key']);
  assert.equal(initialized.code, 0); assert.equal(initialized.stdout, '');
  for (const [name, expected] of [['.', 0o700], ['config.json', 0o600], ['key', 0o600]]) {
    const info = await stat(path.join(configDir, name));
    dump(`${name} permissions`, (info.mode & 0o777).toString(8));
    assert.equal(info.mode & 0o777, expected);
    if (name === 'key') { dump('key byte length', info.size); assert.equal(info.size, 32); }
  }
  pass('private storage and 32-byte key created');

  step('2. Protect repeated, Unicode and multiline text');
  const input = `Draft a reply to ${secret}.\r\n${multiline}\nAgain ${secret}.`;
  const protectedResult = await command(['protect'], input);
  success(protectedResult);
  dump('detector HTTP exchange', detections.at(-1));
  assert.equal(JSON.parse(detections.at(-1).body).messages[1].content, input);
  for (const value of [secret, multiline]) assert.ok(!protectedResult.stdout.includes(value));
  const markers = protectedResult.stdout.match(/\[\[SEALGATE:v1:[A-Za-z0-9_-]+\]\]/g);
  assert.equal(markers.length, 3); assert.equal(new Set(markers).size, 3);
  pass('three distinct ciphertext markers; detector received exact original input');

  step('3. Preserve public text without adding a newline');
  const publicResult = await command(['protect'], 'Public release notes.');
  success(publicResult); assert.equal(publicResult.stdout, 'Public release notes.');
  dump('detector response', detections.at(-1).response);
  pass('no-match stdout is byte-for-byte unchanged');

  step('4. Reject an invalid detector answer and already protected input');
  mode = 'invalid';
  const invalid = await command(['protect'], secret);
  assert.equal(invalid.code, 1); assert.equal(invalid.stdout, '');
  assert.ok(!invalid.stderr.includes(secret));
  dump('detector response', detections.at(-1).response);
  mode = 'valid';
  const beforeReplay = detections.length;
  const replay = await command(['protect'], protectedResult.stdout);
  assert.equal(replay.code, 1); assert.equal(replay.stdout, '');
  assert.equal(detections.length, beforeReplay);
  pass('both failures emit empty stdout; reserved-marker rejection makes no detector call');

  step('5. Forward protected system, prompt, tool input and tool result text');
  const upstream = await listen(async (req, res) => {
    forwarded.push({ method: req.method, url: req.url, headers: req.headers, body: await body(req) });
    res.setHeader('content-type', 'application/json');
    res.end('{"content":[{"type":"text","text":"Synthetic reply"}]}');
  });
  const key = await readFile(path.join(configDir, 'key'));
  const config = makeConfig({ baseUrl: `${detector}/v1`, model: 'synthetic-detector', apiKeyEnv: null });
  const protector = new RequestProtector(key, (text, signal) => detectSensitive(text, config, {}, signal));
  const authorization = 'Bearer synthetic-subscription-token';
  gateway = await startGateway({ protector, authorization, upstream, env: {}, timeoutMs: 5000 });
  const headers = { authorization, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'oauth-2025-04-20', 'content-type': 'application/json' };
  const request = { model: 'claude-test', max_tokens: 128, system: `Contact ${secret}`, messages: [
    { role: 'user', content: `Draft for ${secret}` },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_1', name: 'Read', input: { path: `/data/${secret}` } }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: `File says ${secret}\n${multiline}` }] },
  ] };
  async function send(payload) {
    dump('gateway request headers', headers); dump('gateway request body', JSON.stringify(payload));
    const response = await fetch(`http://127.0.0.1:${gateway.address.port}/v1/messages`, {
      method: 'POST', headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(10000),
    });
    const text = await response.text();
    dump('gateway response status', response.status); dump('gateway response body', text);
    return { status: response.status, text };
  }
  const response = await send(request);
  assert.equal(response.status, 200);
  assert.equal(response.text, '{"content":[{"type":"text","text":"Synthetic reply"}]}');
  assert.equal(forwarded.length, 1);
  dump('detector HTTP exchange', detections.at(-1));
  dump('upstream HTTP request', forwarded[0]);
  for (const value of [secret, '123-45-6789']) assert.ok(!forwarded[0].body.includes(value));
  assert.equal(forwarded[0].headers.authorization, authorization);
  assert.ok(!detections.at(-1).body.includes(authorization));
  const restore = value => typeof value === 'string' ? decryptText(value, key) :
    Array.isArray(value) ? value.map(restore) : value && typeof value === 'object' ?
      Object.fromEntries(Object.entries(value).map(([name, child]) => [name, restore(child)])) : value;
  assert.deepEqual(restore(JSON.parse(forwarded[0].body)), request);
  pass('all supported text protected; local restoration matches original JSON; synthetic OAuth forwarded');

  step('6. Block an unsupported gateway field and detector failure');
  for (const payload of [{ ...request, unsupported_field: 'public text' }, request]) {
    const blocked = await send(payload);
    assert.equal(blocked.status, 400); assert.equal(forwarded.length, 1);
    dump('additional upstream requests', forwarded.length - 1);
    mode = 'invalid';
  }
  mode = 'valid';
  pass('both requests blocked with zero additional upstream calls');

  step('7. Decrypt offline and reject tampered ciphertext');
  await gateway.close(); gateway = undefined;
  for (const server of services) {
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  }
  await unlink(path.join(configDir, 'config.json'));
  console.log('All mock servers stopped and config.json removed; only the local key remains.');
  const decrypted = await command(['decrypt'], protectedResult.stdout);
  success(decrypted); assert.equal(decrypted.stdout, input);
  const tampered = protectedResult.stdout.replace(/(\[\[SEALGATE:v1:)([A-Za-z0-9_-])/, (_, prefix, first) => prefix + (first === 'A' ? 'B' : 'A'));
  const rejected = await command(['decrypt'], tampered);
  assert.equal(rejected.code, 1); assert.equal(rejected.stdout, '');
  pass('offline round trip preserves exact bytes; tampering emits no plaintext');

  step('8. Run the companion plugin SessionStart hook');
  const hook = await command([], '', 'dist/scripts/session-start.js');
  success(hook);
  const reminder = JSON.parse(hook.stdout);
  assert.equal(reminder.hookSpecificOutput.hookEventName, 'SessionStart');
  assert.match(reminder.hookSpecificOutput.additionalContext, /Do not read SEALGATE keys/);
  pass('hook returns the expected reminder without provider configuration');
  console.log('\nPASS: all 8 verification steps completed.');
} finally {
  if (gateway) await gateway.close();
  for (const server of services) {
    if (server.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  }
  await rm(temporary, { recursive: true, force: true });
}
