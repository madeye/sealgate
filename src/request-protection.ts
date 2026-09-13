import { createHmac, randomUUID } from 'node:crypto';
import { detectionRanges } from './detection.js';
import { encryptSpan } from './crypto.js';
import { fail } from './errors.js';
import { isRecord } from './types.js';

export type Detector = (text: string, signal?: AbortSignal) => Promise<unknown>;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
interface Field { text: string; replace?: (text: string) => void }
const TOP_LEVEL = new Set(['model', 'messages', 'system', 'tools', 'tool_choice', 'max_tokens',
  'stream', 'temperature', 'top_p', 'top_k', 'stop_sequences', 'metadata', 'thinking',
  'output_config', 'context_management', 'service_tier', 'cache_control']);
const CONTENT_TYPES = new Set(['text', 'tool_use', 'tool_result', 'tool_reference', 'thinking', 'redacted_thinking']);
const CONTROLS = new Set(['role', 'type', 'model', 'id', 'tool_use_id', 'name', 'tool_name',
  'signature', 'effort', 'service_tier', 'ttl']);
const LIMIT = 1024 * 1024;

/** A session-local ledger. Only exact, already-remote signed blocks can be replayed.
 * Hashes and ciphertext are retained; original local plaintext is never cached. */
export class RequestProtector {
  private readonly ciphertext = new Map<string, string>();
  private readonly remoteBlocks = new Set<string>();
  private readonly issuedMarkers = new Set<string>();
  private cacheBytes = 0;

  constructor(private readonly key: Buffer, private readonly detect: Detector) {}

  private digest(text: string): string {
    return createHmac('sha256', this.key).update(text).digest('hex');
  }

  rememberRemoteBlock(block: unknown): void {
    if (!isRecord(block) || !['thinking', 'redacted_thinking'].includes(String(block.type))) return;
    // Canonicalize keys, but preserve every value. Client-added cache metadata is
    // inspected separately and cannot be smuggled through this exemption.
    const clean = { ...block };
    delete clean.cache_control;
    if (!this.validSignedBlock(clean)) return;
    const canonical = JSON.stringify(clean, Object.keys(clean).sort());
    if (this.remoteBlocks.size >= 4096) this.remoteBlocks.delete(this.remoteBlocks.values().next().value!);
    this.remoteBlocks.add(this.digest(canonical));
  }

  private validSignedBlock(block: Record<string, unknown>): boolean {
    const keys = block.type === 'thinking' ? ['type', 'thinking', 'signature'] : ['type', 'data'];
    return Object.keys(block).length === keys.length && keys.every(key => typeof block[key] === 'string');
  }

  clear(): void {
    this.ciphertext.clear(); this.remoteBlocks.clear(); this.issuedMarkers.clear(); this.cacheBytes = 0;
  }

  private marker(plain: string): string {
    const digest = this.digest(plain);
    const previous = this.ciphertext.get(digest);
    if (previous) return previous;
    const result = encryptSpan(plain, this.key);
    if (this.cacheBytes + result.length > 8 * LIMIT || this.issuedMarkers.size >= 100_000) {
      fail('Gateway encryption cache limit reached; start a new session.');
    }
    this.ciphertext.set(digest, result);
    this.issuedMarkers.add(result);
    this.cacheBytes += result.length;
    return result;
  }

  async protect(input: unknown, controls: string[] = [], signal?: AbortSignal): Promise<{ body: string }> {
    if (!isRecord(input) || Object.keys(input).some(key => !TOP_LEVEL.has(key)) ||
        typeof input.model !== 'string' || !Array.isArray(input.messages)) {
      fail('Gateway rejected an unsupported request schema.');
    }
    // Work on an isolated JSON tree; never partially mutate a caller's request.
    const tree = structuredClone(input) as Record<string, Json>;
    const fields: Field[] = controls.map(text => ({ text }));
    let nodes = 0;

    const textField = (text: string, replace?: (text: string) => void): void => {
      if (!text.isWellFormed()) fail('Gateway requires well-formed Unicode text.');
      // Existing ciphertext is accepted only if this gateway issued it. Never
      // decrypt a marker into the detector, Claude, its history, or tool output.
      const pieces: Array<{ start: number; end: number; marker: string }> = [];
      let cursor = 0;
      while ((cursor = text.indexOf('[[SEALGATE:', cursor)) !== -1) {
        const end = text.indexOf(']]', cursor);
        const marker = text.slice(cursor, end + 2);
        if (end < 0 || !this.issuedMarkers.has(marker)) fail('Gateway rejected an unknown or modified ciphertext marker.');
        pieces.push({ start: cursor, end: end + 2, marker });
        cursor = end + 2;
      }
      if (!pieces.length) { if (text) fields.push({ text, replace }); return; }
      const output: string[] = [];
      cursor = 0;
      for (const piece of [...pieces, { start: text.length, end: text.length, marker: '' }]) {
        const index = output.length;
        output.push(text.slice(cursor, piece.start), piece.marker);
        if (output[index]) fields.push({ text: output[index], replace: replace ? value => {
          output[index] = value; replace(output.join(''));
        } : undefined });
        cursor = piece.end;
      }
    };

    const walk = (value: Json, set: (value: Json) => void, depth: number, data = false, control = false): void => {
      if (++nodes > 100_000 || depth > 64) fail('Gateway request structure exceeds the limit.');
      if (typeof value === 'string') { textField(value, control ? undefined : set); return; }
      if (typeof value === 'number') { fields.push({ text: String(value) }); return; }
      if (value === null || typeof value === 'boolean') return;
      if (Array.isArray(value)) {
        value.forEach((child, index) => walk(child, next => { value[index] = next; }, depth + 1, data, control));
        return;
      }
      if (!isRecord(value)) fail('Gateway requires a JSON request.');
      // No opaque documents, images, URLs, uploads, or server-side containers.
      // Objects inside tool inputs/schema are ordinary data, not content blocks.
      if (!data && ['thinking', 'redacted_thinking'].includes(String(value.type)) &&
          ('signature' in value || 'data' in value || 'thinking' in value)) {
        const clean = { ...value }; delete clean.cache_control;
        if (!this.validSignedBlock(clean) || !this.remoteBlocks.has(this.digest(JSON.stringify(clean, Object.keys(clean).sort())))) {
          fail('Gateway blocks signed content that was not received in this session.');
        }
        if (value.cache_control) walk(value.cache_control, next => { value.cache_control = next; }, depth + 1, false, true);
        return;
      }
      if (!data && ['source', 'data', 'file_id', 'url', 'container', 'mcp_servers'].some(key => key in value)) {
        fail('Gateway blocks opaque content and remote resource references.');
      }
      for (const [key, child] of Object.entries(value)) {
        textField(key); // Sensitive object keys cannot be renamed without changing meaning.
        const childData = data || key === 'input' || key === 'input_schema' || key === 'schema';
        walk(child, next => { value[key] = next; }, depth + 1, childData,
          control || (!childData && CONTROLS.has(key)));
      }
    };

    for (const message of tree.messages as Json[]) {
      if (!isRecord(message) || !['user', 'assistant', 'system'].includes(String(message.role))) {
        fail('Gateway rejected an unsupported message.');
      }
      const content = message.content;
      if (typeof content !== 'string' && !Array.isArray(content)) fail('Gateway rejected unsupported message content.');
      const checkBlocks = (blocks: unknown[]): void => {
        for (const block of blocks) {
          if (!isRecord(block) || !CONTENT_TYPES.has(String(block.type))) fail('Gateway rejected an unsupported content block.');
          if (block.type === 'tool_result' && Array.isArray(block.content)) checkBlocks(block.content);
        }
      };
      if (Array.isArray(content)) checkBlocks(content);
    }
    walk(tree, () => {}, 0);
    // Plain field text avoids JSON escape mismatches for Unicode/newlines. A
    // random delimiter keeps unrelated fields separate; cross-field matches fail.
    const boundary = `\n[SEALGATE field boundary ${randomUUID()}]\n`;
    let offset = 0;
    const positioned = fields.map(field => {
      const start = offset; offset += field.text.length + boundary.length;
      return { ...field, start, end: start + field.text.length };
    });
    const aggregate = fields.map(field => field.text).join(boundary);
    if (Buffer.byteLength(aggregate) > LIMIT) fail('Gateway detection input exceeds 1 MiB; reduce context.');
    const ranges = detectionRanges(aggregate, await this.detect(aggregate, signal));
    if (signal?.aborted) fail('Gateway protection canceled.');
    let index = 0;
    for (const field of positioned) {
      const parts: string[] = [];
      let cursor = field.start;
      while (index < ranges.length && ranges[index].start < field.end) {
        const range = ranges[index++];
        if (!field.replace || range.start < field.start || range.end > field.end) {
          fail('Gateway detected sensitive protocol data or a cross-field span; request blocked.');
        }
        parts.push(aggregate.slice(cursor, range.start), this.marker(aggregate.slice(range.start, range.end)));
        cursor = range.end;
      }
      if (cursor !== field.start) field.replace!(parts.join('') + aggregate.slice(cursor, field.end));
    }
    if (index !== ranges.length) fail('Gateway detection matched a field separator; request blocked.');
    return { body: JSON.stringify(tree) };
  }
}
