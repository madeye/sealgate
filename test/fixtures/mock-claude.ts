#!/usr/bin/env node
import { appendFile } from 'node:fs/promises';

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => args[args.indexOf(name) + 1];
const sessionId = args.includes('--resume') ? flag('--resume') : flag('--session-id');
const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = Buffer.concat(chunks).toString('utf8');
if (process.env.MOCK_RECORD_FILE) await appendFile(process.env.MOCK_RECORD_FILE, JSON.stringify({
  args, input, heccVariables: Object.keys(process.env).filter(name => name.startsWith('HECC_')),
  detectorCredentialPresent: Boolean(process.env.TEST_DETECTOR_TOKEN),
}) + '\n', { mode: 0o600 });

const mode = process.env.MOCK_CLAUDE_MODE;
if (mode === 'hang') {
  setInterval(() => {}, 1000);
} else if (mode === 'bad-json') {
  process.stdout.write('synthetic-private-response-body\n');
} else if (mode === 'error' || mode === 'auth-error' || mode === 'expired-oauth') {
  process.stderr.write('synthetic-private-stderr');
  process.stdout.write(JSON.stringify({ type: 'result', subtype: 'error_during_execution', is_error: true,
    api_error_status: mode === 'expired-oauth' ? null : mode === 'auth-error' ? 401 : 500,
    result: mode === 'expired-oauth' ? 'Synthetic OAuth token expired; synthetic-private-response-body' : 'synthetic-private-response-body', session_id: sessionId }) + '\n');
  process.exitCode = 1;
} else {
  const reply = 'Mock reply 🔐';
  const events = [
    { type: 'system', subtype: 'init', session_id: sessionId },
    ...(mode === 'result-only' ? [] : [{ type: 'stream_event', event: { type: 'content_block_delta', delta: { type: 'text_delta', text: reply } } }]),
    { type: 'result', subtype: 'success', is_error: false, result: reply, session_id: sessionId, permission_denials: mode === 'denied' ? [{}] : [] },
  ];
  // Exercise UTF-8 and JSON split across arbitrary chunks, including a result
  // with no trailing newline.
  const bytes = Buffer.from(events.map(event => JSON.stringify(event)).join('\n'));
  for (let offset = 0; offset < bytes.length; offset += 7) process.stdout.write(bytes.subarray(offset, offset + 7));
}
