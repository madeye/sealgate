import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, realpath } from 'node:fs/promises';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { homedir } from 'node:os';
import { loadSubscription, runSandbox } from '../src/sandbox.js';
import { startGateway } from '../src/gateway.js';
import { RequestProtector } from '../src/request-protection.js';
import { configDirectory, loadConfig } from '../src/config.js';
import { providerSettings } from '../src/env.js';
import { detectSensitive } from '../src/provider.js';
import { temporary, provider } from './helpers.js';

test('subscription loading requires private, current OAuth credentials and preserves the credential', async t => {
  const dir = await temporary(t);
  await assert.rejects(loadSubscription(dir), /subscription login/);
  const credentials = { claudeAiOauth: { accessToken: 'synthetic-subscription-token', expiresAt: Date.now() - 1000 } };
  const file = path.join(dir, '.credentials.json');
  await writeFile(file, JSON.stringify(credentials), { mode: 0o600 });
  await assert.rejects(loadSubscription(dir), /expired/);
  credentials.claudeAiOauth.expiresAt = Date.now() + 60_000;
  await writeFile(file, JSON.stringify(credentials));
  const result = await loadSubscription(dir);
  assert.equal(result.authorization, 'Bearer synthetic-subscription-token');
  assert.deepEqual(JSON.parse(result.credentials), credentials);
});

test('Docker end-to-end: encrypted egress, child TCP/DNS isolation, Unix socket denial, hidden dotenv, and workspace edits', {
  skip: process.env.SEALGATE_TEST_DOCKER !== '1', timeout: 60_000,
}, async t => {
  const runtime = await temporary(t); const workspace = await temporary(t);
  await mkdir(path.join(runtime, 'sockets')); await mkdir(path.join(runtime, 'home'));
  await writeFile(path.join(workspace, '.env'), 'SEALGATE_API_KEY=synthetic-detector-key', { mode: 0o600 });
  let unixConnections = 0;
  const unix = createServer(socket => { unixConnections++; socket.end('host socket'); });
  await new Promise<void>(resolve => unix.listen(path.join(workspace, 'host.sock'), resolve));
  t.after(() => new Promise<void>(resolve => unix.close(() => resolve())));
  const captured: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    captured.push(Buffer.concat(chunks).toString()); res.end('ok');
  })).replace(/\/v1$/, '');
  const protector = new RequestProtector(randomBytes(32), async text => ({ sensitive_substrings: text.includes('synthetic-secret') ? ['synthetic-secret'] : [] }));
  const gateway = await startGateway({ protector, authorization: 'Bearer synthetic-subscription-token', upstream,
    socketPath: path.join(runtime, 'sockets/gateway.sock') });
  t.after(() => gateway.close());
  const code = String.raw`
    const assert=require('node:assert/strict'),fs=require('node:fs'),net=require('node:net'),cp=require('node:child_process');
    (async()=>{
      assert.equal(fs.readFileSync('/workspace/.env','utf8'),'');
      assert.equal(process.env.SEALGATE_API_KEY,undefined);
      assert.equal(process.env.ANTHROPIC_API_KEY,undefined);
      assert.equal(process.env.ANTHROPIC_AUTH_TOKEN,undefined);
      assert.equal(fs.existsSync('/var/run/docker.sock'),false);
      assert.equal(fs.existsSync('/home/mlv/.config/sealgate/key'),false);
      await new Promise((resolve,reject)=>{
        const s=net.connect('/workspace/host.sock',()=>{s.destroy();reject(Error('Unix escape'))});
        s.on('error',e=>{assert.equal(e.code,'EPERM');resolve()});
      });
      const attack=String.raw` + '`' + String.raw`
        const net=require('node:net');
        (async()=>{for(const host of ['1.1.1.1','example.com','172.17.0.1']){
          await new Promise((resolve,reject)=>{const s=net.connect(443,host,()=>{s.destroy();reject(Error('network escape'))});s.setTimeout(1500,()=>{s.destroy();resolve()});s.on('error',resolve)});
        }})().catch(()=>process.exit(1));
      ` + '`' + String.raw`;
      const child=cp.spawnSync('node',['-e',attack],{timeout:10000});assert.equal(child.status,0);
      const response=await fetch(process.env.ANTHROPIC_BASE_URL+'/v1/messages',{
        method:'POST',headers:{authorization:'Bearer synthetic-subscription-token','anthropic-version':'2023-06-01','anthropic-beta':'oauth-2025-04-20','content-type':'application/json'},
        body:JSON.stringify({model:'claude-test',messages:[{role:'user',content:'Contact synthetic-secret'}]})
      });
      assert.equal(response.status,200);assert.equal(await response.text(),'ok');
      assert.equal((await fetch(process.env.ANTHROPIC_BASE_URL+'/telemetry',{method:'POST',body:'synthetic-secret'})).status,403);
      fs.writeFileSync('/workspace/result.txt','sandbox checks passed');
    })().catch(()=>{process.stderr.write('Sandbox probe failed\n');process.exit(1)});
  `;
  const binary = await realpath(process.env.SEALGATE_TEST_CLAUDE ?? path.join(homedir(), '.local/bin/claude'));
  const status = await runSandbox({ runtime, workspace, binary, print: true, command: ['node', '-e', code] });
  assert.equal(status, 0); assert.equal(unixConnections, 0);
  assert.equal(captured.length, 1); assert.ok(!captured[0].includes('synthetic-secret')); assert.ok(captured[0].includes('[[SEALGATE:v1:'));
  assert.equal(await readFile(path.join(workspace, 'result.txt'), 'utf8'), 'sandbox checks passed');
  assert.equal(await readFile(path.join(workspace, '.env'), 'utf8'), 'SEALGATE_API_KEY=synthetic-detector-key');
});

test('native Claude end-to-end through sandbox and mock upstream includes file and tool-result protection', {
  skip: process.env.SEALGATE_TEST_DOCKER !== '1', timeout: process.env.SEALGATE_TEST_LIVE === '1' ? 900_000 : 120_000,
}, async t => {
  const runtime = await temporary(t); const workspace = await temporary(t);
  await mkdir(path.join(runtime, 'sockets')); await mkdir(path.join(runtime, 'home/.claude'), { recursive: true });
  await writeFile(path.join(runtime, 'home/.claude/.credentials.json'), JSON.stringify({ claudeAiOauth: {
    accessToken: 'synthetic-subscription-token', refreshToken: 'synthetic-refresh-token', expiresAt: Date.now() + 3600_000,
    scopes: ['user:inference', 'user:profile'], subscriptionType: 'max', rateLimitTier: 'default_claude_max_5x',
  } }), { mode: 0o600 });
  await writeFile(path.join(runtime, 'home/.claude.json'), JSON.stringify({ hasCompletedOnboarding: true,
    oauthAccount: { accountUuid: '11111111-1111-4111-8111-111111111111', organizationUuid: '22222222-2222-4222-8222-222222222222', emailAddress: 'synthetic@example.test' },
  }), { mode: 0o600 });
  await writeFile(path.join(workspace, 'CLAUDE.md'), 'Project contact: system-secret@example.test\n');
  await writeFile(path.join(workspace, 'private.txt'), 'File contact: tool-secret@example.test\n');
  const bodies: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString(); bodies.push(body);
    assert.equal(req.headers.authorization, 'Bearer synthetic-subscription-token');
    const tool = !JSON.parse(body).messages.some((message: { content: unknown }) => Array.isArray(message.content) && message.content.some(block => block.type === 'tool_result'));
    const content = tool ? { type: 'tool_use', id: 'toolu_synthetic1', name: 'Read', input: { file_path: '/workspace/private.txt' } }
      : { type: 'text', text: 'Synthetic end-to-end success.' };
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const emit = (event: Record<string, unknown>) => res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
    emit({ type: 'message_start', message: { id: 'msg_synthetic', type: 'message', role: 'assistant', model: 'claude-sonnet-4-6', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 0 } } });
    emit({ type: 'content_block_start', index: 0, content_block: tool ? { ...content, input: {} } : { type: 'text', text: '' } });
    emit({ type: 'content_block_delta', index: 0, delta: tool ? { type: 'input_json_delta', partial_json: JSON.stringify(content.input) } : { type: 'text_delta', text: content.text } });
    emit({ type: 'content_block_stop', index: 0 });
    emit({ type: 'message_delta', delta: { stop_reason: tool ? 'tool_use' : 'end_turn', stop_sequence: null }, usage: { output_tokens: 10 } });
    emit({ type: 'message_stop' }); res.end();
  })).replace(/\/v1$/, '');
  const detected: string[] = [];
  const live = process.env.SEALGATE_TEST_LIVE === '1' ? await providerSettings(await loadConfig(configDirectory())) : undefined;
  const protector = new RequestProtector(randomBytes(32), async (text, signal) => {
    const secrets = ['system-secret@example.test', 'tool-secret@example.test', 'prompt-secret@example.test'].filter(secret => text.includes(secret));
    detected.push(...secrets);
    if (live) {
      process.stderr.write('Live vLLM: inspecting a native Claude request.\n');
      return detectSensitive(text, live.config, live.env, signal);
    }
    return { sensitive_substrings: secrets };
  });
  const gateway = await startGateway({ protector, authorization: 'Bearer synthetic-subscription-token', upstream, socketPath: path.join(runtime, 'sockets/gateway.sock') });
  t.after(() => gateway.close());
  const binary = await realpath(process.env.SEALGATE_TEST_CLAUDE ?? path.join(homedir(), '.local/bin/claude'));
  // Prompt is delivered through stdin by an in-container harness, never argv.
  const code = `const cp=require('node:child_process');const r=cp.spawnSync('claude',['--print','--model','claude-sonnet-4-6','--tools','Read','--allowedTools','Read','--setting-sources','project,local','--strict-mcp-config'],{input:'Read private.txt. Prompt contact: prompt-secret@example.test',encoding:'utf8',timeout:${live ? 800_000 : 80_000}});if(r.status!==0||!r.stdout.includes('Synthetic end-to-end success.')){process.stderr.write('Native Claude smoke failed\\n');process.exit(1)}`;
  const status = await runSandbox({ runtime, workspace, binary, print: true, command: ['node', '-e', code] });
  assert.equal(status, 0);
  assert.ok(bodies.length >= 2);
  for (const secret of ['system-secret@example.test', 'tool-secret@example.test', 'prompt-secret@example.test']) {
    assert.ok(detected.includes(secret), 'native context reached detector');
    assert.ok(bodies.every(body => !body.includes(secret)), 'plaintext excluded from upstream');
  }
});
