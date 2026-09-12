import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { fail } from './errors.js';
import { detectionRanges } from './detection.js';

const PREFIX = '[[HECC:';
const AAD = Buffer.from('hecc:v1', 'ascii');

function validateKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('Encryption key must contain exactly 32 bytes.');
}

export function encryptSpan(plaintext: string, key: Buffer): string {
  validateKey(key);
  try {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const payload = Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString('base64url');
    return `[[HECC:v1:${payload}]]`;
  } catch {
    fail('Encryption failed; no protected prompt was produced.');
  }
}

export function validatePrompt(prompt: string): void {
  if (!prompt.isWellFormed()) fail('Input must be valid UTF-8 text.');
  if (prompt.includes(PREFIX)) fail('Input contains a reserved HECC marker; protect original plaintext only.');
}

export function protectText(prompt: string, result: unknown, key: Buffer): string {
  validateKey(key);
  validatePrompt(prompt);
  const ranges = detectionRanges(prompt, result);
  const parts: string[] = [];
  let cursor = 0;
  for (const { start, end } of ranges) {
    parts.push(prompt.slice(cursor, start), encryptSpan(prompt.slice(start, end), key));
    cursor = end;
  }
  parts.push(prompt.slice(cursor));
  return parts.join('');
}

export function decryptText(text: string, key: Buffer): string {
  validateKey(key);
  const parts: string[] = [];
  let cursor = 0;
  let start: number;
  while ((start = text.indexOf(PREFIX, cursor)) !== -1) {
    const end = text.indexOf(']]', start);
    const marker = end < 0 ? '' : text.slice(start, end + 2);
    const match = /^\[\[HECC:v1:([A-Za-z0-9_-]+)\]\]$/.exec(marker);
    if (!match) fail('Malformed or unsupported HECC marker; no plaintext was produced.');
    try {
      const payload = Buffer.from(match[1], 'base64url');
      if (payload.length < 29 || payload.toString('base64url') !== match[1]) throw new Error();
      const decipher = createDecipheriv('aes-256-gcm', key, payload.subarray(0, 12), { authTagLength: 16 });
      decipher.setAAD(AAD);
      decipher.setAuthTag(payload.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]);
      parts.push(text.slice(cursor, start), new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
    } catch {
      fail('Decryption failed: incorrect key or damaged ciphertext; no plaintext was produced.');
    }
    cursor = end + 2;
  }
  parts.push(text.slice(cursor));
  return parts.join('');
}
