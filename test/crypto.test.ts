import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { detectionRanges } from '../src/detection.js';
import { encryptSpan, protectText, decryptText } from '../src/crypto.js';

const detection = (...values: unknown[]): { sensitive_substrings: unknown[] } => ({ sensitive_substrings: values });

test('repeated substrings are all replaced with independent ciphertext', () => {
  const key = randomBytes(32);
  const prompt = 'Email synthetic@example.test; repeat synthetic@example.test.\n';
  const protectedText = protectText(prompt, detection('synthetic@example.test', 'synthetic@example.test'), key);
  const markers = protectedText.match(/\[\[HECC:v1:[\w-]+\]\]/g);
  assert.ok(markers);
  assert.equal(markers.length, 2);
  assert.notEqual(markers[0], markers[1]);
  assert.equal(protectedText, `Email ${markers[0]}; repeat ${markers[1]}.\n`);
  assert.ok(!protectedText.includes('synthetic@example.test'));
  assert.equal(decryptText(protectedText, key), prompt);
});

test('overlapping, nested, and self-overlapping matches merge', () => {
  assert.deepEqual(detectionRanges('0123456789', detection('2345', '4567', '34')), [{ start: 2, end: 8 }]);
  assert.deepEqual(detectionRanges('ababa', detection('aba')), [{ start: 0, end: 5 }]);
  assert.deepEqual(detectionRanges('aaa', detection('aa')), [{ start: 0, end: 3 }]);
  const key = randomBytes(32);
  const result = protectText('x ababa y', detection('aba', 'bab'), key);
  assert.equal(result.match(/\[\[HECC:/g)?.length, 1);
  assert.equal(decryptText(result, key), 'x ababa y');
});

test('Unicode, combining characters, BOMs, multiline and adjacent spans round trip exactly', () => {
  const key = randomBytes(32);
  const prompt = '\uFEFFHello 👩🏽‍💻 秘密\r\n<confidential>\nCafé\n財務\n</confidential>\nend';
  const values = ['👩🏽‍💻', '秘密', '<confidential>\nCafé\n財務\n</confidential>'];
  const result = protectText(prompt, detection(...values), key);
  for (const value of values) assert.ok(!result.includes(value));
  assert.equal(decryptText(result, key), prompt);
  const adjacent = protectText('AB', detection('A', 'B'), key);
  assert.equal(decryptText(adjacent, key), 'AB');
  assert.equal(decryptText(encryptSpan('\uFEFFsecret', key), key), '\uFEFFsecret');
});

test('no matches preserve all text, including empty input and whitespace', () => {
  const key = randomBytes(32);
  for (const prompt of ['', '\n \r\n', 'A public sentence.']) {
    assert.equal(protectText(prompt, detection(), key), prompt);
    assert.equal(decryptText(prompt, key), prompt);
  }
});

test('invalid detection data is rejected instead of silently ignoring entries', () => {
  for (const result of [null, [], {}, { sensitive_substrings: null }, { sensitive_substrings: [], extra: true },
    detection(''), detection(1), detection({}), detection('absent'), detection('\ud83d'), detection('ok', 'absent')]) {
    assert.throws(() => detectionRanges('ok 😀', result));
  }
  assert.throws(() => detectionRanges('aa', detection(...Array(10_001).fill('a'))));
  assert.throws(() => detectionRanges('a'.repeat(100_001), detection('a')));
  assert.throws(() => protectText('[[HECC:v1:existing]]', detection(), randomBytes(32)));
});

test('AES-GCM rejects a wrong key and changes to nonce, tag, or ciphertext', () => {
  const key = randomBytes(32);
  const marker = encryptSpan('synthetic secret', key);
  assert.equal(decryptText(marker, key), 'synthetic secret');
  assert.notEqual(encryptSpan('synthetic secret', key), marker);
  assert.throws(() => decryptText(marker, randomBytes(32)));
  const payload = Buffer.from(marker.slice('[[HECC:v1:'.length, -2), 'base64url');
  for (const index of [0, 12, 28]) {
    const changed = Buffer.from(payload);
    changed[index] ^= 1;
    assert.throws(() => decryptText(`[[HECC:v1:${changed.toString('base64url')}]]`, key));
  }
  assert.throws(() => encryptSpan('secret', Buffer.alloc(31)));
  assert.throws(() => protectText('public', detection(), Buffer.alloc(0)));
});

test('malformed, truncated, noncanonical, and unsupported markers fail', () => {
  const key = randomBytes(32);
  const valid = encryptSpan('secret', key);
  for (const marker of ['[[HECC:', '[[HECC:v1:]]', '[[HECC:v1:abc]]', '[[HECC:v1:!]]',
    valid.replace('v1', 'v2'), valid.slice(0, -1), valid.replace(']]', '=]]')]) {
    assert.throws(() => decryptText(`surrounding ${valid} then ${marker}`, key));
  }
});
