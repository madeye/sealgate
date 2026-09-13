import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, realpath, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { isElf, isMachO, loadSubscription, prepareRuntime } from '../src/launcher.js';
import type { Runtime } from '../src/launcher.js';
import { extraRules, seatbeltParams, buildProfile, runSeatbelt } from '../src/seatbelt.js';
import { startGateway } from '../src/gateway.js';
import { RequestProtector } from '../src/request-protection.js';
import { startProxyForwarder } from '../src/proxy.js';
import { validateConfig, makeConfig, configDirectory, loadConfig } from '../src/config.js';
import { providerSettings } from '../src/env.js';
import { detectSensitive } from '../src/provider.js';
import { SealgateError } from '../src/errors.js';
import { temporary, provider, mockProxy } from './helpers.js';
import type { TestContext } from 'node:test';

const gated = { skip: process.platform !== 'darwin' || process.env.SEALGATE_TEST_SEATBELT !== '1' };
const CRLF = '\\r\\n';
const subscription = { authorization: 'Bearer synthetic-subscription-token', account: { emailAddress: 'synthetic@example.test' },
  credentials: JSON.stringify({ claudeAiOauth: { accessToken: 'synthetic-subscription-token', refreshToken: 'synthetic-refresh-token',
    expiresAt: Date.now() + 3600_000, scopes: ['user:inference', 'user:profile'], subscriptionType: 'max' } }) };

test('executable format detection and Keychain-backed subscription loading', async t => {
  assert.ok(isElf(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))); assert.ok(!isMachO(Buffer.from([0x7f, 0x45, 0x4c, 0x46])));
  assert.ok(isMachO(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))); assert.ok(isMachO(Buffer.from([0xca, 0xfe, 0xba, 0xbe])));
  assert.ok(!isElf(Buffer.from([0xcf, 0xfa, 0xed, 0xfe])));
  const dir = await temporary(t);
  const keychain = async () => JSON.stringify({ claudeAiOauth: { accessToken: 'keychain-token', expiresAt: Date.now() + 60_000 } });
  const loaded = await loadSubscription(dir, { keychain });
  assert.equal(loaded.authorization, 'Bearer keychain-token');
  await assert.rejects(loadSubscription(dir, { keychain: async () => undefined }), /subscription login/);
  await assert.rejects(loadSubscription(dir, { keychain: async () => 'not json' }), /subscription login/);
  await assert.rejects(loadSubscription(dir, { keychain: async () => JSON.stringify({ claudeAiOauth: { accessToken: 'x', expiresAt: 1 } }) }), /expired/);
  // An existing private file wins over the Keychain, matching Claude's own order.
  await writeFile(path.join(dir, '.credentials.json'), JSON.stringify({ claudeAiOauth: { accessToken: 'file-token', expiresAt: Date.now() + 60_000 } }), { mode: 0o600 });
  assert.equal((await loadSubscription(dir, { keychain })).authorization, 'Bearer file-token');
});

test('profile parameters are validated and never interpolated; extra rules reference parameters only', async t => {
  const base = makeConfig({ baseUrl: 'http://127.0.0.1:8000/v1', model: 'm', apiKeyEnv: null });
  assert.deepEqual(validateConfig({ ...base, sandboxReadPaths: ['/opt/tools'] }).sandboxReadPaths, ['/opt/tools']);
  for (const bad of [['relative'], ['/x\ty'], 'string', Array.from({ length: 33 }, (_, i) => `/p${i}`)]) {
    assert.throws(() => validateConfig({ ...base, sandboxReadPaths: bad }), SealgateError);
  }
  const rules = extraRules({ READ0: '/opt/tools', TEMP: '/private/var/folders/ab/cd/T' }, 4321);
  assert.equal(rules, '(allow network-outbound (remote ip "localhost:4321"))\n(allow file-read* (subpath (param "READ0")))\n(allow file-read* file-write* (regex #"^/private/var/folders/ab/cd/T/xcrun_db"))');
  assert.match(extraRules({ TEMP: '/tmp with space' }, 1, 2), /localhost:2/);
  assert.ok(!extraRules({ TEMP: '/tmp with space' }, 1).includes('xcrun'));
  assert.throws(() => extraRules({ TEMP: '/t' }, 70000), SealgateError);
  const profile = await buildProfile({ TEMP: '/private/tmp' }, 5);
  assert.ok(profile.startsWith(';; SEALGATE macOS sandbox profile')); assert.ok(!profile.includes('@@EXTRA_RULES@@'));
  assert.ok(profile.includes('(deny default)') && profile.includes('"localhost:5"'));
  const workspace = await temporary(t); const runtime = await prepareRuntime(subscription, await realpath(workspace));
  t.after(() => rm(runtime.dir, { recursive: true, force: true }));
  const keyDir = await temporary(t);
  const options = { workspace, runtime, binary: process.execPath, keyDir, readPaths: [] as string[], gatewayPort: 1 };
  const params = await seatbeltParams(options);
  assert.equal(params.WORKSPACE, await realpath(workspace)); assert.equal(params.KEYDIR, await realpath(keyDir));
  assert.ok(params.RUNTIME.startsWith('/') && params.BIN.startsWith('/') && params.TEMP.startsWith('/'));
  await assert.rejects(seatbeltParams({ ...options, readPaths: [homedir()] }), /home directory/);
  await assert.rejects(seatbeltParams({ ...options, readPaths: [keyDir] }), /key directory/);
  await assert.rejects(seatbeltParams({ ...options, readPaths: [path.join(keyDir, 'missing')] }), /does not exist/);
  await assert.rejects(seatbeltParams({ ...options, workspace: homedir() }), /home directory/);
  await assert.rejects(seatbeltParams({ ...options, workspace: path.dirname(homedir()) }), /home directory/);
});

test('session supervisor refuses to launch a command outside its sandbox even with IPC', async t => {
  const workspace = await temporary(t);
  const child = spawn(process.execPath, [
    fileURLToPath(new URL('../scripts/seatbelt-supervisor.js', import.meta.url)),
    '/bin/sh', '-c', 'echo unexpected > launched.txt',
  ], { cwd: workspace, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  assert.deepEqual(await once(child, 'close'), [1, null]);
  await assert.rejects(readFile(path.join(workspace, 'launched.txt')), { code: 'ENOENT' });
});

async function claudeBinary(): Promise<string> {
  return realpath(process.env.SEALGATE_TEST_CLAUDE ?? path.join(homedir(), '.local/bin/claude'));
}

async function sandboxRuntime(t: TestContext, workspace: string): Promise<Runtime> {
  const runtime = await prepareRuntime(subscription, await realpath(workspace));
  t.after(() => rm(runtime.dir, { recursive: true, force: true }));
  return runtime;
}

test('Seatbelt end-to-end: encrypted egress, network and IPC denial, hidden secrets, opt-in reads and workspace edits', { ...gated, timeout: 120_000 }, async t => {
  const workspace = await realpath(await temporary(t)); const keyDir = await temporary(t); const readable = await temporary(t);
  await writeFile(path.join(keyDir, 'key'), randomBytes(32), { mode: 0o600 });
  await writeFile(path.join(readable, 'tool.txt'), 'opt-in readable');
  await writeFile(path.join(workspace, '.env'), 'SEALGATE_API_KEY=synthetic-detector-key', { mode: 0o600 });
  let unixConnections = 0;
  const unix = createServer(socket => { unixConnections++; socket.end('host socket'); });
  await new Promise<void>(resolve => unix.listen(path.join(workspace, 'host.sock'), resolve));
  t.after(() => new Promise<void>(resolve => unix.close(() => resolve())));
  let loopbackConnections = 0;
  const other = createServer(socket => { loopbackConnections++; socket.end('other host service'); });
  await new Promise<void>(resolve => other.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => other.close(() => resolve())));
  const otherPort = (other.address() as { port: number }).port;
  const captured: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    captured.push(Buffer.concat(chunks).toString()); res.end('ok');
  })).replace(/\/v1$/, '');
  const plainPort = Number(new URL(upstream).port);
  const proxy = await mockProxy(t, (host, port) => host === 'upstream.test' ? { host: '127.0.0.1', port } : undefined);
  const forwarder = await startProxyForwarder(new URL(proxy.url), { loopback: true });
  t.after(() => forwarder.close());
  const protector = new RequestProtector(randomBytes(32), async text => ({ sensitive_substrings: text.includes('synthetic-secret') ? ['synthetic-secret'] : [] }));
  const gateway = await startGateway({ protector, authorization: 'Bearer synthetic-subscription-token', upstream });
  t.after(() => gateway.close());
  const gatewayPort = (gateway.address as { port: number }).port;
  const runtime = await sandboxRuntime(t, workspace);
  const binary = await claudeBinary();
  const probe = (proxyMode: boolean) => `
    const assert=require('node:assert/strict'),fs=require('node:fs'),net=require('node:net'),cp=require('node:child_process'),dns=require('node:dns'),os=require('node:os'),path=require('node:path');
    const HOME=${JSON.stringify(homedir())},KEY=${JSON.stringify(path.join(keyDir, 'key'))},READ=${JSON.stringify(path.join(readable, 'tool.txt'))};
    const denied=fn=>{try{fn()}catch(e){if(e.code==='EPERM'||e.code==='EACCES')return;throw e}throw Error('expected denial: '+fn)};
    const refused=(port,host,unixPath)=>new Promise((resolve,reject)=>{const s=unixPath?net.connect(unixPath):net.connect(port,host);s.setTimeout(3000,()=>{s.destroy();resolve()});s.on('connect',()=>{s.destroy();reject(Error('unexpected connection to '+(unixPath||host+':'+port)))});s.on('error',()=>resolve())});
    (async()=>{
      assert.equal(process.env.HOME,${JSON.stringify(runtime.home)});assert.equal(process.env.CLAUDE_CONFIG_DIR,path.join(process.env.HOME,'.claude'));
      assert.equal(process.env.SEALGATE_API_KEY,undefined);assert.equal(process.env.ANTHROPIC_API_KEY,undefined);assert.equal(process.env.ANTHROPIC_AUTH_TOKEN,undefined);
      assert.equal(process.env.ANTHROPIC_BASE_URL,'http://127.0.0.1:${gatewayPort}');
      assert.equal(process.env.HTTPS_PROXY,${proxyMode ? `'http://127.0.0.1:${forwarder.port}'` : 'undefined'});
      denied(()=>fs.readFileSync(KEY));denied(()=>fs.readFileSync(${JSON.stringify(path.join(workspace, '.env'))}));denied(()=>fs.readdirSync(path.join(HOME,'Library')));
      denied(()=>fs.readFileSync(path.join(HOME,'.claude.json')));
      denied(()=>fs.writeFileSync(path.join(HOME,'sealgate-probe'),'x'));denied(()=>fs.writeFileSync('/Users/Shared/sealgate-probe','x'));
      denied(()=>fs.writeFileSync(path.join(path.dirname(READ),'new.txt'),'x'));
      assert.equal(fs.readFileSync(READ,'utf8'),'opt-in readable');
      assert.equal(fs.realpathSync('.'),${JSON.stringify(workspace)});
      fs.writeFileSync('result.txt','sandbox checks passed');
      const tmp=path.join(os.tmpdir(),'probe');fs.writeFileSync(tmp,'t');fs.unlinkSync(tmp);
      fs.writeFileSync('child.js','process.send("hi");');
      await new Promise((resolve,reject)=>{const c=cp.fork('child.js');c.on('message',m=>{assert.equal(m,'hi');resolve()});c.on('error',reject);c.on('exit',code=>{if(code!==0)reject(Error('fork exit '+code))})});
      assert.equal(cp.spawnSync('/bin/sh',['-c','echo x > /dev/stdout && echo y >&2']).status,0);
      for(const [file,args] of [['/usr/bin/open',['http://127.0.0.1:1/']],['/usr/bin/osascript',['-e','tell application "System Events" to get name of first process']],['/bin/launchctl',['submit','-l','sealgate-probe','--','/usr/bin/true']]]){
        const r=cp.spawnSync(file,args,{timeout:15000});assert.notEqual(r.status,0,file+' should fail');
      }
      const keychain=cp.spawnSync('/usr/bin/security',['find-generic-password','-s','Claude Code-credentials','-w'],{encoding:'utf8',timeout:15000});assert.equal(keychain.stdout.trim(),'');
      const pb=cp.spawnSync('/usr/bin/pbpaste',{encoding:'utf8',timeout:15000});assert.equal((pb.stdout||'').length,0);
      await refused(443,'1.1.1.1');await refused(${otherPort},'127.0.0.1');await refused(0,'',${JSON.stringify(path.join(workspace, 'host.sock'))});
      await new Promise(resolve=>dns.lookup('example.com',(err)=>{assert.ok(err,'DNS must fail');resolve()}));
      await new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',()=>resolve());s.listen(0,'127.0.0.1',()=>{s.close();reject(Error('listen should fail'))})});
      const response=await fetch(process.env.ANTHROPIC_BASE_URL+'/v1/messages',{method:'POST',headers:{authorization:'Bearer synthetic-subscription-token','anthropic-version':'2023-06-01','anthropic-beta':'oauth-2025-04-20','content-type':'application/json'},body:JSON.stringify({model:'claude-test',messages:[{role:'user',content:'Contact synthetic-secret'}]})});
      assert.equal(response.status,200);assert.equal(await response.text(),'ok');
      assert.equal((await fetch(process.env.ANTHROPIC_BASE_URL+'/telemetry',{method:'POST',body:'synthetic-secret'})).status,403);
      const tunnel=()=>new Promise((resolve,reject)=>{const s=net.connect(${forwarder.port},'127.0.0.1');let head='';s.setTimeout(5000,()=>{s.destroy();reject(Error('tunnel timeout'))});s.on('connect',()=>s.write('CONNECT upstream.test:${plainPort} HTTP/1.1${CRLF}Host: upstream.test:${plainPort}${CRLF}${CRLF}'));s.on('data',d=>{head+=d;if(head.includes('${CRLF}${CRLF}')){s.destroy();resolve(head.split(' ')[1])}});s.on('error',reject)});
      if(${proxyMode}){assert.equal(await tunnel(),'200')}else{await refused(${forwarder.port},'127.0.0.1')}
    })().catch(e=>{process.stderr.write('Sandbox probe failed: '+(e&&e.stack||e)+String.fromCharCode(10));process.exit(1)});
  `;
  const base = { workspace, runtime, binary, keyDir, readPaths: [readable], gatewayPort, print: true };
  assert.equal(await runSeatbelt({ ...base, command: [process.execPath, '-e', probe(false)] }), 0);
  assert.equal(await runSeatbelt({ ...base, proxyPort: forwarder.port, command: [process.execPath, '-e', probe(true)] }), 0);
  assert.equal(unixConnections, 0); assert.equal(loopbackConnections, 0);
  assert.equal(captured.length, 2); assert.ok(captured.every(body => !body.includes('synthetic-secret') && body.includes('[[SEALGATE:v1:')));
  assert.deepEqual(proxy.log, [`upstream.test:${plainPort}`]);
  assert.equal(await readFile(path.join(workspace, 'result.txt'), 'utf8'), 'sandbox checks passed');
  assert.equal(await readFile(path.join(workspace, '.env'), 'utf8'), 'SEALGATE_API_KEY=synthetic-detector-key');
});

test('native Claude end-to-end under Seatbelt with mock upstream includes file and tool-result protection', {
  ...gated, timeout: process.env.SEALGATE_TEST_LIVE === '1' ? 900_000 : 180_000,
}, async t => {
  const workspace = await realpath(await temporary(t)); const keyDir = await temporary(t);
  await writeFile(path.join(workspace, 'CLAUDE.md'), 'Project contact: system-secret@example.test\n');
  await writeFile(path.join(workspace, 'private.txt'), 'File contact: tool-secret@example.test\n');
  const bodies: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString(); bodies.push(body);
    assert.equal(req.headers.authorization, 'Bearer synthetic-subscription-token');
    const tool = !JSON.parse(body).messages.some((message: { content: unknown }) => Array.isArray(message.content) && message.content.some(block => block.type === 'tool_result'));
    const content = tool ? { type: 'tool_use', id: 'toolu_synthetic1', name: 'Read', input: { file_path: path.join(workspace, 'private.txt') } }
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
      process.stderr.write('Live detector: inspecting a native Claude request.\n');
      return detectSensitive(text, live.config, live.env, signal);
    }
    return { sensitive_substrings: secrets };
  });
  const gateway = await startGateway({ protector, authorization: 'Bearer synthetic-subscription-token', upstream });
  t.after(() => gateway.close());
  const runtime = await sandboxRuntime(t, workspace);
  const binary = await claudeBinary();
  // Prompt is delivered through stdin by an in-sandbox harness, never argv.
  const code = `const cp=require('node:child_process');const r=cp.spawnSync(${JSON.stringify(binary)},['--print','--model','claude-sonnet-4-6','--tools','Read','--allowedTools','Read','--setting-sources','project,local','--strict-mcp-config'],{input:'Read private.txt. Prompt contact: prompt-secret@example.test',encoding:'utf8',timeout:${live ? 800_000 : 150_000}});if(r.status!==0||!r.stdout.includes('Synthetic end-to-end success.')){process.stderr.write('Native Claude smoke failed: status '+r.status+String.fromCharCode(10)+(r.stderr||'').slice(-2000)+String.fromCharCode(10));process.exit(1)}`;
  const status = await runSeatbelt({ workspace, runtime, binary, keyDir, readPaths: [], gatewayPort: (gateway.address as { port: number }).port, print: true, command: [process.execPath, '-e', code] });
  assert.equal(status, 0);
  assert.ok(bodies.length >= 2);
  for (const secret of ['system-secret@example.test', 'tool-secret@example.test', 'prompt-secret@example.test']) {
    assert.ok(detected.includes(secret), 'native context reached detector');
    assert.ok(bodies.every(body => !body.includes(secret)), 'plaintext excluded from upstream');
  }
});

test('Seatbelt reaps detached double-fork tools without touching other sessions or host processes', { ...gated, timeout: 15000 }, async t => {
  const workspace = await realpath(await temporary(t)); const keyDir = await temporary(t);
  const runtime = await sandboxRuntime(t, workspace);
  const otherWorkspace = await realpath(await temporary(t));
  const otherRuntime = await sandboxRuntime(t, otherWorkspace);
  const other = runSeatbelt({ workspace: otherWorkspace, runtime: otherRuntime, keyDir, binary: process.execPath,
    readPaths: [], gatewayPort: 1, command: ['/bin/sh', '-c', 'sleep 3; echo alive > other.txt'] });
  const host = spawn('/bin/sleep', ['10'], { stdio: 'ignore' });
  t.after(() => host.kill());
  const detached = `const c=require('node:child_process').spawn('/bin/sh',
    ['-c','echo ready > ready.txt; sleep 2; echo escaped > escaped.txt'],
    {detached:true,stdio:'ignore',env:{}});c.unref();`;
  const root = `const cp=require('node:child_process'),fs=require('node:fs');
    cp.spawnSync(${JSON.stringify(process.execPath)},['-e',${JSON.stringify(detached)}]);
    const deadline=Date.now()+3000;
    while(!fs.existsSync('ready.txt')&&Date.now()<deadline){}
    process.exit(fs.existsSync('ready.txt')?7:8);`;
  assert.equal(await runSeatbelt({ workspace, runtime, keyDir, binary: process.execPath, readPaths: [], gatewayPort: 1,
    command: [process.execPath, '-e', root] }), 7);
  assert.equal(await other, 0);
  assert.equal(await readFile(path.join(otherWorkspace, 'other.txt'), 'utf8'), 'alive\n');
  assert.equal(host.exitCode, null); assert.equal(host.signalCode, null);
  await assert.rejects(readFile(path.join(workspace, 'escaped.txt')), { code: 'ENOENT' });
});

test('Seatbelt cancellation reaps detached tools even when the client ignores SIGTERM', { ...gated, timeout: 15000 }, async t => {
  const workspace = await realpath(await temporary(t)); const keyDir = await temporary(t);
  const runtime = await sandboxRuntime(t, workspace);
  const client = `const c=require('node:child_process').spawn('/bin/sh',
    ['-c','echo ready > ready.txt; sleep 4; echo escaped > escaped.txt'],{detached:true,stdio:'ignore'});
    c.unref();process.on('SIGTERM',()=>{});setTimeout(()=>process.exit(0),8000);`;
  const options = { workspace, runtime, keyDir, binary: process.execPath, readPaths: [], gatewayPort: 1,
    command: [process.execPath, '-e', client] };
  const harness = spawn(process.execPath, ['--input-type=module', '-e',
    `import {runSeatbelt} from ${JSON.stringify(new URL('../src/seatbelt.js', import.meta.url).href)};
     process.exitCode=await runSeatbelt(JSON.parse(process.argv[1]));`, JSON.stringify(options)], { stdio: 'ignore' });
  t.after(() => harness.kill('SIGTERM'));
  const closed = once(harness, 'close');
  const deadline = Date.now() + 4000;
  while (true) {
    try { await readFile(path.join(workspace, 'ready.txt')); break; }
    catch { assert.ok(Date.now() < deadline, 'client did not start'); await delay(25); }
  }
  harness.kill('SIGTERM');
  assert.deepEqual(await closed, [143, null]);
  await delay(4200);
  await assert.rejects(readFile(path.join(workspace, 'escaped.txt')), { code: 'ENOENT' });
});
