import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, lstat, rm, copyFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { fail } from './errors.js';
import type { ProviderSettings } from './types.js';
import { detectSensitive } from './provider.js';
import { RequestProtector } from './request-protection.js';
import { startGateway } from './gateway.js';
import { proxyFromEnvironment, startProxyForwarder } from './proxy.js';
import type { Forwarder } from './proxy.js';
import { CLAUDE_ARGS, RELAY_GATEWAY_PORT, RELAY_PROXY_PORT, claudeEnvironment, findNativeClaude, foreground,
  isElf, isMachO, loadSubscription, prepareRuntime, sandboxDirectory } from './launcher.js';
import { checkSeatbelt, runSeatbelt } from './seatbelt.js';

export { loadSubscription, sandboxDirectory } from './launcher.js';
export type { Subscription } from './launcher.js';

const execute = promisify(execFile);
export const SANDBOX_IMAGE = 'sealgate-sandbox:0.4.0';

async function docker(args: string[]): Promise<string> {
  try { return (await execute('docker', args, { timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout.trim(); }
  catch { fail('Docker sandbox operation failed. Check the local daemon and run sealgate sandbox-build.'); }
}

export async function checkDocker(): Promise<void> {
  if (process.platform !== 'linux' || !['arm64', 'x64'].includes(process.arch)) fail('The enforced launcher requires macOS ARM64/x86-64 or Linux with Docker.');
  const context = await docker(['context', 'inspect', '--format', '{{(index .Endpoints "docker").Host}}']);
  if (!context.startsWith('unix://') || process.env.DOCKER_HOST && !process.env.DOCKER_HOST.startsWith('unix://')) {
    fail('SEALGATE requires a local Docker daemon; remote Docker would expose plaintext.');
  }
  await docker(['info', '--format', '{{.ServerVersion}}']);
}

export async function buildSandbox(): Promise<void> {
  if (process.platform === 'darwin') { process.stderr.write('sealgate: macOS uses the built-in sandbox; no image build is needed.\n'); return; }
  await checkDocker();
  // A small, separate build context never includes the project, .env, or keys.
  const context = await mkdtemp(path.join(tmpdir(), 'sealgate-build-'));
  try {
    await copyFile(path.join(sandboxDirectory, 'Dockerfile'), path.join(context, 'Dockerfile'));
    await copyFile(fileURLToPath(new URL('../scripts/relay.js', import.meta.url)), path.join(context, 'relay.mjs'));
    if (await foreground('docker', ['build', '--tag', SANDBOX_IMAGE, context]) !== 0) fail('Sandbox image build failed.');
  } finally { await rm(context, { recursive: true, force: true }); }
}

function mount(source: string, target: string, readonly = false): string[] {
  if (source.includes(',') || target.includes(',')) fail('Docker bind paths must not contain commas.');
  return ['--mount', `type=bind,src=${source},dst=${target}${readonly ? ',readonly' : ''}`];
}

export interface SandboxOptions {
  workspace: string;
  runtime: string;
  binary: string;
  model?: string;
  print?: boolean;
  /** Expose the relay's proxy port; the host forwards sockets/proxy.sock to the configured proxy. */
  proxyEgress?: boolean;
  /** Controlled test injection; never exposed as arbitrary CLI arguments. */
  command?: string[];
}

/** Runs the native client and all descendant tools in a networkless namespace.
 * A separate relay alone can open the host gateway socket. Seccomp denies Unix
 * sockets in the client, including sockets hidden in a writable workspace. */
export async function runSandbox(options: SandboxOptions): Promise<number> {
  const uid = process.getuid!(); const gid = process.getgid!();
  const relay = `sealgate-relay-${randomUUID()}`; const client = `sealgate-claude-${randomUUID()}`;
  const base = ['--rm', '--pull=never', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
    '--pids-limit=256', '--user', `${uid}:${gid}`, '--log-driver=none'];
  const home = path.join(options.runtime, 'home');
  // Runtime socket directory and credentials are separate mounts. The relay
  // sees neither the workspace nor the client's subscription credential.
  const sockets = path.join(options.runtime, 'sockets');
  await copyFile(path.join(sandboxDirectory, 'seccomp.json'), path.join(options.runtime, 'seccomp.json'));
  try {
    await docker(['run', '-d', '--name', relay, ...base, '--network=none',
      ...mount(sockets, '/run/sealgate', true), SANDBOX_IMAGE]);
    // Probe the listening socket inside the isolated network, without contacting
    // the gateway or passing any user text. Retries are bounded by the CLI call.
    await docker(['exec', relay, 'node', '-e',
      `const net=require('node:net');let n=0;function probe(){const s=net.connect(${RELAY_GATEWAY_PORT},'127.0.0.1',()=>{s.destroy();process.exit(0)});s.on('error',()=>{if(++n>50)process.exit(1);setTimeout(probe,100)})}probe()`]);
    const environment = { HOME: '/home/sealgate', TERM: 'xterm-256color',
      ...claudeEnvironment(`http://127.0.0.1:${RELAY_GATEWAY_PORT}`, options.proxyEgress ? `http://127.0.0.1:${RELAY_PROXY_PORT}` : undefined) };
    const args = ['run', '--name', client, ...base, '--network', `container:${relay}`,
      '--security-opt', `seccomp=${path.join(options.runtime, 'seccomp.json')}`,
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
      ...mount(options.workspace, '/workspace'), ...mount(home, '/home/sealgate'),
      ...mount(options.binary, '/usr/local/bin/claude', true),
      '--workdir=/workspace', ...Object.entries(environment).map(([name, value]) => `--env=${name}=${value}`)];
    // The detector's .env is loaded by the host and hidden from Claude's tools.
    try { await lstat(path.join(options.workspace, '.env')); args.push(...mount('/dev/null', '/workspace/.env', true)); }
    catch { /* No dotenv file to mask. */ }
    args.push('-i');
    if (process.stdin.isTTY && process.stdout.isTTY && !options.print) args.push('-t');
    args.push(SANDBOX_IMAGE, ...(options.command ?? ['claude', ...CLAUDE_ARGS]));
    if (!options.command) {
      if (options.model) args.push('--model', options.model);
      if (options.print) args.push('--print');
    }
    return await foreground('docker', args);
  } finally {
    // Also kill detached descendants after terminal cancellation/client crashes.
    await docker(['rm', '-f', client]).catch(() => {});
    await docker(['rm', '-f', relay]).catch(() => {});
  }
}

export interface LaunchOptions {
  model?: string;
  print?: boolean;
  proxyEgress?: boolean;
}

export async function launchClaude(settings: ProviderSettings, key: Buffer, configDir: string, options: LaunchOptions = {}): Promise<number> {
  const darwin = process.platform === 'darwin';
  if (darwin) await checkSeatbelt();
  else { await checkDocker(); await docker(['image', 'inspect', SANDBOX_IMAGE, '--format', '{{.Id}}']); }
  const subscription = await loadSubscription();
  const binary = darwin
    ? await findNativeClaude(isMachO, 'The enforced launcher requires the native macOS Claude binary. Install it with claude install.')
    : await findNativeClaude(isElf, 'The enforced launcher requires the native Linux Claude binary. Install it with claude install.');
  const workspace = await realpath(process.cwd());
  const privateDir = await realpath(configDir);
  if (privateDir === workspace || privateDir.startsWith(workspace + path.sep)) fail('The encryption key must be outside the mounted workspace.');
  if (!options.print && (!process.stdin.isTTY || !process.stdout.isTTY)) fail('Use sealgate claude --print for piped input.');
  const proxy = options.proxyEgress ? proxyFromEnvironment(process.env) : undefined;
  if (options.proxyEgress && !proxy) fail('--proxy-egress requires HTTPS_PROXY or HTTP_PROXY set to an http://host:port proxy.');
  const runtime = await prepareRuntime(subscription, workspace);
  let gateway: Awaited<ReturnType<typeof startGateway>> | undefined;
  let forwarder: Forwarder | undefined;
  try {
    const protector = new RequestProtector(key, (text, signal) => detectSensitive(text, settings.config, settings.env, signal));
    const notice = (): void => {
      process.stderr.write('sealgate: Native Claude is isolated. Model requests are inspected; other network access is blocked.\n');
      if (proxy) process.stderr.write('sealgate: --proxy-egress lets tools reach your HTTP proxy. That traffic is not inspected or encrypted.\n');
    };
    if (darwin) {
      gateway = await startGateway({ protector, authorization: subscription.authorization, env: process.env });
      if (!gateway.address || typeof gateway.address === 'string') fail('Gateway did not open a loopback port.');
      if (proxy) forwarder = await startProxyForwarder(proxy, { loopback: true });
      notice();
      return await runSeatbelt({ workspace, runtime, binary, keyDir: privateDir, readPaths: settings.config.sandboxReadPaths ?? [],
        gatewayPort: gateway.address.port, proxyPort: forwarder?.port, model: options.model, print: options.print });
    }
    gateway = await startGateway({ protector, authorization: subscription.authorization, socketPath: path.join(runtime.sockets, 'gateway.sock'), env: process.env });
    if (proxy) forwarder = await startProxyForwarder(proxy, { socketPath: path.join(runtime.sockets, 'proxy.sock') });
    notice();
    return await runSandbox({ workspace, runtime: runtime.dir, binary, proxyEgress: Boolean(proxy), model: options.model, print: options.print });
  } finally {
    await forwarder?.close();
    await gateway?.close();
    await rm(runtime.dir, { recursive: true, force: true });
  }
}
