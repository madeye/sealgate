import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ProtectedChat, claudeEnvironment } from '../src/chat.js';
import type { ChatCallbacks } from '../src/chat.js';
import { runClaude } from '../src/claude.js';
import type { ClaudeOptions } from '../src/claude.js';
import { makeConfig } from '../src/config.js';
import { decryptText } from '../src/crypto.js';
import { answer, cli, compiledRoot, provider, temporary } from './helpers.js';
import { displayText, wrapText } from '../src/tui.js';

const mockOptions = (env: NodeJS.ProcessEnv = {}): ClaudeOptions => ({
  executable: process.execPath,
  executableArgs: [path.join(compiledRoot, 'test/fixtures/mock-claude.js')],
  env: { ...process.env, ...env },
});
const callbacks = (): ChatCallbacks & { protected: string[]; replies: string[] } => {
  const result = {
    protected: [] as string[], replies: [] as string[],
    onProtected: (value: string): void => { result.protected.push(value); },
    onText: (value: string): void => { result.replies.push(value); },
    onActivity: (): void => {},
  };
  return result;
};
interface RecordedCall { args: string[]; input: string; sealgateVariables: string[]; detectorCredentialPresent: boolean }
async function calls(file: string): Promise<RecordedCall[]> {
  return (await readFile(file, 'utf8')).trim().split('\n').map(line => JSON.parse(line) as RecordedCall);
}

test('chat protects each turn, passes only ciphertext on stdin, and resumes its own session', async t => {
  const dir = await temporary(t);
  const record = path.join(dir, 'calls.jsonl');
  const key = randomBytes(32);
  const baseUrl = await provider(t, (req, res) => answer(res, { sensitive_substrings: ['synthetic@example.test'] }));
  const chat = new ProtectedChat({ config: makeConfig({ baseUrl, model: 'detector', apiKeyEnv: 'TEST_DETECTOR_TOKEN' }), env: { TEST_DETECTOR_TOKEN: 'synthetic-key' } }, key,
    mockOptions({ MOCK_RECORD_FILE: record, SEALGATE_API_KEY: 'synthetic-key', TEST_DETECTOR_TOKEN: 'synthetic-key' }));
  const events = callbacks();
  const first = 'Draft a reply to synthetic@example.test.\n';
  const second = 'Now shorten the reply to synthetic@example.test.\n';
  await chat.send(first, events);
  await chat.send(second, events);
  const recorded = await calls(record);
  assert.equal(recorded.length, 2);
  for (const [index, call] of recorded.entries()) {
    assert.ok(!call.input.includes('synthetic@example.test'));
    assert.ok(!call.args.join(' ').includes('synthetic@example.test'));
    assert.deepEqual(call.sealgateVariables, []);
    assert.equal(call.detectorCredentialPresent, false);
    assert.equal(decryptText(call.input, key), index === 0 ? first : second);
    assert.equal(call.args[call.args.indexOf('--permission-mode') + 1], 'dontAsk');
    assert.ok(!call.args.includes('--dangerously-skip-permissions'));
    assert.ok(!call.args.includes('--continue'));
  }
  const session = recorded[0].args[recorded[0].args.indexOf('--session-id') + 1];
  assert.equal(recorded[1].args[recorded[1].args.indexOf('--resume') + 1], session);
  assert.deepEqual(events.replies, ['Mock reply 🔐', 'Mock reply 🔐']);
  chat.reset();
  await chat.send(first, callbacks());
  const third = (await calls(record))[2];
  assert.ok(third.args.includes('--session-id'));
  assert.notEqual(third.args[third.args.indexOf('--session-id') + 1], session);
});

test('invalid detection never starts Claude and cancellation interrupts detection', async t => {
  const dir = await temporary(t);
  const record = path.join(dir, 'calls.jsonl');
  let hang = false;
  const baseUrl = await provider(t, (req, res) => { if (!hang) answer(res, { sensitive_substrings: ['not in the prompt'] }); });
  const chat = new ProtectedChat({ config: makeConfig({ baseUrl, model: 'test', apiKeyEnv: null }), env: {} }, randomBytes(32), mockOptions({ MOCK_RECORD_FILE: record }));
  const events = callbacks();
  await assert.rejects(chat.send('synthetic secret', events), /did not match/);
  assert.deepEqual(events.protected, []);
  await assert.rejects(readFile(record), { code: 'ENOENT' });
  hang = true;
  const controller = new AbortController();
  const pending = chat.send('synthetic secret', events, controller.signal);
  controller.abort();
  await assert.rejects(pending, /canceled/);
  await assert.rejects(readFile(record), { code: 'ENOENT' });
});

test('Claude errors reset conversation state and keep response bodies out of diagnostics', async t => {
  const dir = await temporary(t);
  const record = path.join(dir, 'calls.jsonl');
  const baseUrl = await provider(t, (req, res) => answer(res, { sensitive_substrings: [] }));
  const options = mockOptions({ MOCK_RECORD_FILE: record });
  const chat = new ProtectedChat({ config: makeConfig({ baseUrl, model: 'test', apiKeyEnv: null }), env: {} }, randomBytes(32), options);
  await chat.send('public input', callbacks());
  options.env = { ...options.env, MOCK_CLAUDE_MODE: 'error' };
  await assert.rejects(chat.send('public followup', callbacks()), error => {
    assert.ok(error instanceof Error);
    assert.ok(!error.message.includes('synthetic-private'));
    return true;
  });
  options.env = { ...options.env, MOCK_CLAUDE_MODE: 'result-only' };
  await chat.send('public retry', callbacks());
  const recorded = await calls(record);
  assert.ok(recorded[1].args.includes('--resume'));
  assert.ok(recorded[2].args.includes('--session-id'));
  assert.notEqual(recorded[0].args.at(-1), recorded[2].args.at(-1));
});

test('Claude transport handles final-only output, permission denials, bad JSON, missing executable, timeout and abort', async () => {
  for (const mode of ['result-only', 'denied']) {
    const text: string[] = [];
    const result = await runClaude('protected input', { sessionId: randomUUID(), resume: false, onText: value => text.push(value) }, mockOptions({ MOCK_CLAUDE_MODE: mode }));
    assert.equal(text.join(''), 'Mock reply 🔐');
    assert.equal(result.permissionDenials, mode === 'denied' ? 1 : 0);
  }
  await assert.rejects(runClaude('protected input', { sessionId: randomUUID(), resume: false }, mockOptions({ MOCK_CLAUDE_MODE: 'bad-json' })), /invalid/);
  await assert.rejects(runClaude('protected input', { sessionId: randomUUID(), resume: false }, mockOptions({ MOCK_CLAUDE_MODE: 'auth-error' })), /claude auth login/);
  await assert.rejects(runClaude('protected input', { sessionId: randomUUID(), resume: false }, mockOptions({ MOCK_CLAUDE_MODE: 'expired-oauth' })), /claude auth login/);
  await assert.rejects(runClaude('protected input', { sessionId: randomUUID(), resume: false }, { executable: '/does/not/exist' }), /start Claude/);
  await assert.rejects(runClaude('protected input', { sessionId: randomUUID(), resume: false }, { ...mockOptions({ MOCK_CLAUDE_MODE: 'hang' }), timeoutMs: 100 }), /timed out/);
  const controller = new AbortController();
  const pending = runClaude('protected input', { sessionId: randomUUID(), resume: false, signal: controller.signal }, mockOptions({ MOCK_CLAUDE_MODE: 'hang' }));
  controller.abort();
  await assert.rejects(pending, /canceled/);
});

test('TUI display neutralizes terminal controls and wraps Unicode without breaking graphemes', async t => {
  assert.equal(displayText('\x1b]52;c;payload\x07\u202Ehello'), ']52;c;payloadhello');
  assert.equal(displayText('Email [[SEALGATE:v1:abc123]]'), 'Email [encrypted]');
  assert.deepEqual(wrapText('a秘密b', 3), ['a秘', '密b']);
  assert.deepEqual(wrapText('👩🏽‍💻ab', 2), ['👩🏽‍💻', 'ab']);
  const result = await cli(['chat'], '', await temporary(t));
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /interactive terminal/);
  assert.deepEqual(claudeEnvironment({ SEALGATE_API_KEY: 'hidden', CUSTOM_DETECTOR: 'hidden', ANTHROPIC_API_KEY: 'claude-key' }, 'CUSTOM_DETECTOR'), { ANTHROPIC_API_KEY: 'claude-key' });
});
