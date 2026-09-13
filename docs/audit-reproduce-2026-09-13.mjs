// Synthetic, local-only audit probes. Run from any directory after npm run build.
// Results describe observed defects; this is not a passing regression suite.
import { createServer } from 'node:net';
import { createServer as httpServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtemp, realpath, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { request } from '../dist/src/http.js';
import { connectViaProxy, startProxyForwarder } from '../dist/src/proxy.js';
import { prepareRuntime } from '../dist/src/launcher.js';
import { runSeatbelt } from '../dist/src/seatbelt.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise(resolve => server.close(resolve));
const output = (id, result) => console.log(JSON.stringify({ id, ...result }));

// F1: CONNECT succeeds, but the peer never completes TLS.
{
  const sockets = new Set();
  let connected;
  const ready = new Promise(resolve => { connected = resolve; });
  const proxy = createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      socket.once('data', connected);
    });
  });
  await listen(proxy);
  const controller = new AbortController();
  let settled = false;
  const pending = request(new URL('https://upstream.test/'), {
    method: 'POST', body: 'synthetic', headers: {}, signal: controller.signal,
    env: { HTTPS_PROXY: `http://127.0.0.1:${proxy.address().port}` },
  }).then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.race([ready, delay(2000).then(() => { throw Error('No TLS ClientHello'); })]);
    controller.abort();
    await delay(500);
    output('F1', { requestSettledAfterAbort: settled, openProxySockets: sockets.size });
  } finally {
    controller.abort();
    for (const socket of sockets) socket.destroy();
    await pending;
    await close(proxy);
  }
}

// F2: Only configured synthetic credentials satisfy this local proxy.
{
  const seen = [];
  const proxy = httpServer();
  proxy.on('connect', (req, socket) => {
    seen.push(Boolean(req.headers['proxy-authorization']));
    socket.end(req.headers['proxy-authorization']
      ? 'HTTP/1.1 200 OK\r\n\r\n'
      : 'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
  });
  await listen(proxy);
  const url = new URL(`http://synthetic:password@127.0.0.1:${proxy.address().port}`);
  const forwarder = await startProxyForwarder(url, { loopback: true });
  let refused = false;
  try {
    try {
      const socket = await connectViaProxy(new URL(`http://127.0.0.1:${forwarder.port}`), 'upstream.test', 443);
      socket.destroy();
    } catch { refused = true; }
    const direct = await connectViaProxy(url, 'upstream.test', 443);
    direct.destroy();
    output('F2', { forwardedTunnelRefused: refused, forwardedAuth: seen[0], directAuth: seen[1] });
  } finally { await forwarder.close(); await close(proxy); }
}

// F3: Use a subprocess so the uncaught exception cannot interrupt other probes.
{
  const source = `
    import {createServer} from 'node:net';
    import {parseProxyUrl,connectViaProxy} from './dist/src/proxy.js';
    const server=createServer(()=>{});
    await new Promise(r=>server.listen(0,'127.0.0.1',r));
    try {
      await connectViaProxy(parseProxyUrl('http://user:%@127.0.0.1:'+server.address().port),'upstream.test',443);
    } catch { console.log('caught rejection'); server.close(); }
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: root, encoding: 'utf8', timeout: 3000,
  });
  output('F3', { exit: result.status, promiseCatchReached: result.stdout.includes('caught rejection'),
    uncaughtURIError: result.stderr.includes('URIError: URI malformed') });
}

// F4: The child has a bounded lifetime and writes only in a fresh scratch directory.
if (process.platform === 'darwin') {
  const workspace = await realpath(await mkdtemp(path.join(tmpdir(), 'sealgate-audit-work-')));
  const keyDir = await mkdtemp(path.join(tmpdir(), 'sealgate-audit-key-'));
  const runtime = await prepareRuntime({ credentials: '{}', authorization: 'Bearer synthetic', account: {} }, workspace);
  try {
    const status = await runSeatbelt({ workspace, keyDir, runtime, binary: process.execPath,
      readPaths: [], gatewayPort: 1, command: [process.execPath, '-e', `
        const child=require('node:child_process').spawn('/bin/sh',
          ['-c','sleep 1; echo synthetic > survived.txt'],{detached:true,stdio:'ignore'});
        child.unref();
      `] });
    await rm(runtime.dir, { recursive: true, force: true });
    await delay(1500);
    let survived = false;
    try { survived = (await readFile(path.join(workspace, 'survived.txt'), 'utf8')).trim() === 'synthetic'; } catch {}
    output('F4', { launcherExit: status, workspaceWrittenAfterExit: survived });
  } finally {
    await rm(runtime.dir, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
    await rm(keyDir, { recursive: true, force: true });
  }
} else output('F4', { skipped: 'Requires macOS' });
