import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, realpath } from 'node:fs/promises';
import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { homedir } from 'node:os';
import { loadSubscription, runSandbox } from '../src/sandbox.js';
import { startGateway } from '../src/gateway.js';
import { RequestProtector } from '../src/request-protection.js';
import { configDirectory, loadConfig } from '../src/config.js';
import { providerSettings } from '../src/env.js';
import { detectSensitive } from '../src/provider.js';
import { temporary, provider, mockProxy } from './helpers.js';
import { startProxyForwarder } from '../src/proxy.js';
import { ProviderNetworkPolicy } from '../src/provider-network.js';

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

test('Docker end-to-end: protected model requests, direct child TCP/DNS, Unix socket denial, hidden dotenv, and workspace edits', {
  skip: process.env.SEALGATE_TEST_DOCKER !== '1', timeout: 60_000,
}, async t => {
  const runtime = await temporary(t); const workspace = await temporary(t);
  await mkdir(path.join(runtime, 'sockets')); await mkdir(path.join(runtime, 'home'));
  await writeFile(path.join(workspace, '.env'), 'SEALGATE_API_KEY=synthetic-detector-key', { mode: 0o600 });
  let unixConnections = 0;
  const unix = createServer(socket => { unixConnections++; socket.end('host socket'); });
  await new Promise<void>(resolve => unix.listen(path.join(workspace, 'host.sock'), resolve));
  t.after(() => new Promise<void>(resolve => unix.close(() => resolve())));
  // Host fixtures exercise egress out of the container without public services.
  const bridgeHost = (await promisify(execFile)('docker', ['network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}'])).stdout.trim();
  let directConnections = 0;
  const direct = createServer(socket => { directConnections++; socket.end('direct tool traffic'); });
  await new Promise<void>(resolve => direct.listen(0, '0.0.0.0', resolve));
  t.after(() => new Promise<void>(resolve => direct.close(() => resolve())));
  const directAddress = direct.address();
  assert.ok(directAddress && typeof directAddress !== 'string');
  let dnsQueries = 0;
  const dns = createSocket('udp4');
  dns.on('message', (query, peer) => {
    dnsQueries++;
    // Echo the question and return a single A record for tool.test.
    const response = Buffer.concat([query, Buffer.from('c00c000100010000003c0004c000022a', 'hex')]);
    response.writeUInt16BE(0x8180, 2); response.writeUInt16BE(1, 6);
    dns.send(response, peer.port, peer.address);
  });
  await new Promise<void>(resolve => dns.bind(0, '0.0.0.0', resolve));
  t.after(() => new Promise<void>(resolve => dns.close(resolve)));
  const captured: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    captured.push(Buffer.concat(chunks).toString()); res.end('ok');
  })).replace(/\/v1$/, '');
  const plainPort = Number(new URL(upstream).port);
  const providerPolicy = new ProviderNetworkPolicy(async () => ['127.0.0.2', '::1']);
  const proxy = await mockProxy(t, (host, port) => host === '127.0.0.1' ? { host, port } : undefined);
  const forwarder = await startProxyForwarder(new URL(proxy.url), { socketPath: path.join(runtime, 'sockets/proxy.sock') }, host => providerPolicy.blocks(host));
  t.after(() => forwarder.close());
  const protector = new RequestProtector(randomBytes(32), async text => ({ sensitive_substrings: text.includes('synthetic-secret') ? ['synthetic-secret'] : [] }));
  const gateway = await startGateway({ protector, authorization: 'Bearer synthetic-subscription-token', upstream,
    socketPath: path.join(runtime, 'sockets/gateway.sock') });
  t.after(() => gateway.close());
  const CRLF = '\\r\\n';
  const code = (proxyMode: boolean) => String.raw`
    const assert=require('node:assert/strict'),fs=require('node:fs'),net=require('node:net'),cp=require('node:child_process');
    (async()=>{
      assert.equal(fs.readFileSync('/workspace/.env','utf8'),'');
      assert.equal(process.env.SEALGATE_API_KEY,undefined);
      assert.equal(process.env.ANTHROPIC_API_KEY,undefined);
      assert.equal(process.env.ANTHROPIC_AUTH_TOKEN,undefined);
      assert.equal(fs.existsSync('/var/run/docker.sock'),false);
      assert.equal(fs.existsSync('/home/mlv/.config/sealgate/key'),false);
      assert.throws(()=>fs.appendFileSync('/etc/hosts','\n127.0.0.1 api.anthropic.com\n'));
      assert.deepEqual((await require('node:dns/promises').lookup('api.anthropic.com',{all:true})).map(x=>x.address).sort(),['127.0.0.2','::1']);
      assert.notEqual(cp.spawnSync('nft',['flush','ruleset']).status,0);
      const originalProvider=[];
      let providerConnections=0;
      for(const host of ['127.0.0.2','::1']){
        const server=net.createServer(s=>{providerConnections++;s.destroy()});
        await new Promise(resolve=>server.listen(0,host,resolve));originalProvider.push(server);
        const targets=host==='127.0.0.2'?[host,'::ffff:127.0.0.2','api.anthropic.com']:[host];
        for(const target of targets){
          await new Promise((resolve,reject)=>{
            const s=net.connect({port:server.address().port,host:target,autoSelectFamily:false},()=>{s.destroy();reject(Error('provider bypass'))});
            s.setTimeout(500,()=>{s.destroy();resolve()});
            s.on('error',error=>{assert.ok(['EHOSTUNREACH','ENETUNREACH','EACCES','EPERM','ECONNREFUSED'].includes(error.code),target+': '+error.code);resolve()});
          });
        }
      }
      assert.equal(providerConnections,0);
      for(const server of originalProvider) await new Promise(resolve=>server.close(resolve));
      const udp=require('node:dgram').createSocket('udp4');let providerDatagrams=0;
      udp.on('message',()=>providerDatagrams++);
      await new Promise(resolve=>udp.bind(0,'127.0.0.2',resolve));
      udp.send('uninspected',udp.address().port,'127.0.0.2',()=>{});
      await new Promise(resolve=>setTimeout(resolve,50));
      assert.equal(providerDatagrams,0);await new Promise(resolve=>udp.close(resolve));
      await new Promise((resolve,reject)=>{
        const s=net.connect('/workspace/host.sock',()=>{s.destroy();reject(Error('Unix escape'))});
        s.on('error',e=>{assert.equal(e.code,'EPERM');resolve()});
      });
      const tool=String.raw` + '`' + String.raw`
        const assert=require('node:assert/strict'),net=require('node:net'),{Resolver}=require('node:dns/promises');
        (async()=>{
          const resolver=new Resolver({timeout:2000,tries:1});
          resolver.setServers(['${bridgeHost}:${dns.address().port}']);
          assert.deepEqual(await resolver.resolve4('tool.test'),['192.0.2.42']);
          const body=await new Promise((resolve,reject)=>{
            const s=net.connect(${directAddress.port},'${bridgeHost}');let body='';
            s.setTimeout(5000,()=>s.destroy(Error('direct TCP timeout')));
            s.on('data',chunk=>body+=chunk);s.on('end',()=>resolve(body));s.on('error',reject);
          });
          assert.equal(body,'direct tool traffic');
        })().catch(()=>process.exit(1));
      ` + '`' + String.raw`;
      const child=cp.spawnSync('node',['-e',tool],{timeout:10000});assert.equal(child.status,0);
      const response=await fetch(process.env.ANTHROPIC_BASE_URL+'/v1/messages',{
        method:'POST',headers:{authorization:'Bearer synthetic-subscription-token','anthropic-version':'2023-06-01','anthropic-beta':'oauth-2025-04-20','content-type':'application/json'},
        body:JSON.stringify({model:'claude-test',messages:[{role:'user',content:'Contact synthetic-secret'}]})
      });
      assert.equal(response.status,200);assert.equal(await response.text(),'ok');
      assert.equal((await fetch(process.env.ANTHROPIC_BASE_URL+'/telemetry',{method:'POST',body:'synthetic-secret'})).status,403);
      assert.equal(process.env.HTTPS_PROXY,${proxyMode ? "'http://127.0.0.1:17841'" : 'undefined'});
      if(${proxyMode}){
      assert.equal(process.env.NO_PROXY,'127.0.0.1,localhost');
      const tunnel=target=>new Promise((resolve,reject)=>{const s=net.connect(17841,'127.0.0.1');let head='';s.setTimeout(5000,()=>{s.destroy();reject(Error('tunnel timeout'))});s.on('connect',()=>s.write('CONNECT '+target+' HTTP/1.1${CRLF}Host: '+target+'${CRLF}${CRLF}'));s.on('data',d=>{head+=d;if(head.includes('${CRLF}${CRLF}')){s.destroy();resolve(head.split(' ')[1])}});s.on('error',reject)});
      assert.equal(await tunnel('127.0.0.1:${plainPort}'),'200');
      for(const target of ['api.anthropic.com:443','127.0.0.2:443','[::1]:443','[::ffff:127.0.0.2]:443']) assert.equal(await tunnel(target),'403');
      }
      fs.writeFileSync('/workspace/result.txt','sandbox checks passed');
    })().catch(error=>{process.stderr.write('Synthetic sandbox probe failed: '+error.stack+'\n');process.exit(1)});
  `;
  const binary = await realpath(process.env.SEALGATE_TEST_CLAUDE ?? path.join(homedir(), '.local/bin/claude'));
  for (const proxyEgress of [false, true]) {
    const status = await runSandbox({ runtime, workspace, binary, print: true, providerPolicy, proxyEgress, command: ['node', '-e', code(proxyEgress)] });
    assert.equal(status, 0);
  }
  assert.equal(directConnections, 2); assert.equal(dnsQueries, 2);
  assert.equal(unixConnections, 0); assert.deepEqual(proxy.log, [`127.0.0.1:${plainPort}`]);
  assert.equal(captured.length, 2);
  assert.ok(captured.every(body => !body.includes('synthetic-secret') && body.includes('[[SEALGATE:v1:')));
  assert.equal(await readFile(path.join(workspace, 'result.txt'), 'utf8'), 'sandbox checks passed');
  assert.equal(await readFile(path.join(workspace, '.env'), 'utf8'), 'SEALGATE_API_KEY=synthetic-detector-key');
});

test('native Claude keeps model requests protected while Read and networked Bash tools run', {
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
  const bridgeHost = (await promisify(execFile)('docker', ['network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}'])).stdout.trim();
  let toolConnections = 0;
  const toolServer = createServer(socket => { toolConnections++; socket.end('network-secret@example.test'); });
  await new Promise<void>(resolve => toolServer.listen(0, '0.0.0.0', resolve));
  t.after(() => new Promise<void>(resolve => toolServer.close(() => resolve())));
  const toolAddress = toolServer.address();
  assert.ok(toolAddress && typeof toolAddress !== 'string');
  await writeFile(path.join(workspace, 'network-tool.cjs'), `const net=require('node:net');const s=net.connect(${toolAddress.port},${JSON.stringify(bridgeHost)});s.pipe(process.stdout);s.setTimeout(5000,()=>s.destroy(Error('timeout')));s.on('error',()=>process.exit(1));`);
  const bodies: string[] = [];
  const upstream = (await provider(t, async (req, res) => {
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString(); bodies.push(body);
    assert.equal(req.headers.authorization, 'Bearer synthetic-subscription-token');
    const results = JSON.parse(body).messages.flatMap((message: { content: unknown }) => Array.isArray(message.content)
      ? message.content.filter(block => block.type === 'tool_result') : []);
    const tool = results.length < 2;
    const content = results.length === 0 ? { type: 'tool_use', id: 'toolu_synthetic1', name: 'Read', input: { file_path: '/workspace/private.txt' } }
      : results.length === 1 ? { type: 'tool_use', id: 'toolu_synthetic2', name: 'Bash', input: { command: 'node /workspace/network-tool.cjs', description: 'Read the local test network service' } }
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
    const secrets = ['system-secret@example.test', 'tool-secret@example.test', 'prompt-secret@example.test', 'network-secret@example.test'].filter(secret => text.includes(secret));
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
  const code = `const cp=require('node:child_process');const r=cp.spawnSync('claude',['--print','--model','claude-sonnet-4-6','--tools','Read,Bash','--allowedTools','Read,Bash','--setting-sources','project,local','--strict-mcp-config'],{input:'Read private.txt and run node /workspace/network-tool.cjs. Prompt contact: prompt-secret@example.test',encoding:'utf8',timeout:${live ? 800_000 : 80_000}});if(r.status!==0||!r.stdout.includes('Synthetic end-to-end success.')){process.stderr.write('Native Claude smoke failed\\n');process.exit(1)}`;
  const providerPolicy = new ProviderNetworkPolicy(async () => ['127.0.0.2', '::1']);
  const status = await runSandbox({ runtime, workspace, binary, print: true, providerPolicy, command: ['node', '-e', code] });
  assert.equal(status, 0);
  assert.equal(toolConnections, 1, 'native Bash tool reached the network outside SEALGATE');
  assert.ok(bodies.length >= 3);
  for (const secret of ['system-secret@example.test', 'tool-secret@example.test', 'prompt-secret@example.test', 'network-secret@example.test']) {
    assert.ok(detected.includes(secret), 'native context reached detector');
    assert.ok(bodies.every(body => !body.includes(secret)), 'plaintext excluded from upstream');
  }
});

test('Docker refresh adds provider addresses, retains old blocks, and stops the client on DNS failure', {
  skip: process.env.SEALGATE_TEST_DOCKER !== '1', timeout: 30_000,
}, async t => {
  const runtime = await temporary(t); const workspace = await temporary(t);
  await mkdir(path.join(runtime, 'sockets')); await mkdir(path.join(runtime, 'home'));
  const providerPolicy = new ProviderNetworkPolicy(async () => {
    let phase = '';
    try { phase = await readFile(path.join(workspace, 'phase'), 'utf8'); } catch { /* Client has not started. */ }
    if (phase === 'fail') throw new Error('synthetic DNS failure');
    return phase === 'refresh' ? ['127.0.0.3'] : ['127.0.0.2'];
  });
  const code = String.raw`
    const assert=require('node:assert/strict'),fs=require('node:fs'),net=require('node:net');
    (async()=>{
      const servers=[];
      for(const host of ['127.0.0.2','127.0.0.3']){
        const s=net.createServer(c=>c.end());await new Promise(r=>s.listen(0,host,r));servers.push(s);
      }
      const reachable=s=>new Promise((resolve,reject)=>{
        const c=net.connect(s.address().port,s.address().address,()=>{c.destroy();resolve(true)});
        c.setTimeout(1000,()=>{c.destroy();reject(Error('timeout'))});c.on('error',()=>resolve(false));
      });
      assert.equal(await reachable(servers[0]),false);
      assert.equal(await reachable(servers[1]),true);
      fs.writeFileSync('/workspace/phase','refresh');
      const deadline=Date.now()+10000;
      while(await reachable(servers[1])){assert.ok(Date.now()<deadline);await new Promise(r=>setTimeout(r,100))}
      assert.equal(await reachable(servers[0]),false);
      fs.writeFileSync('/workspace/phase','fail');
      setInterval(()=>{},1000);
    })().catch(()=>process.exit(1));
  `;
  const binary = await realpath(process.execPath);
  await assert.rejects(runSandbox({ runtime, workspace, binary, providerPolicy, providerRefreshMs: 100,
    print: true, command: ['node', '-e', code] }), /network block refresh failed/);
  assert.equal(await readFile(path.join(workspace, 'phase'), 'utf8'), 'fail');
  assert.deepEqual([...providerPolicy.addresses], ['127.0.0.2', '127.0.0.3']);
});
