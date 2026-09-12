import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, realpath, lstat, rm, access, copyFile, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { fail, HeccError } from './errors.js';
import { isRecord } from './types.js';
import type { ProviderSettings } from './types.js';
import { detectSensitive } from './provider.js';
import { RequestProtector } from './request-protection.js';
import { startGateway } from './gateway.js';

const execute = promisify(execFile);
export const SANDBOX_IMAGE = 'hecc-sandbox:0.3.0';
export const sandboxDirectory = fileURLToPath(new URL('../../sandbox/', import.meta.url));

async function docker(args: string[]): Promise<string> {
  try { return (await execute('docker', args, { timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout.trim(); }
  catch { fail('Docker sandbox operation failed. Check the local daemon and run hecc sandbox-build.'); }
}

export async function checkDocker(): Promise<void> {
  if (process.platform !== 'linux' || !['arm64', 'x64'].includes(process.arch)) fail('The enforced launcher requires Linux ARM64 or x86-64 and Docker.');
  const context = await docker(['context', 'inspect', '--format', '{{(index .Endpoints "docker").Host}}']);
  if (!context.startsWith('unix://') || process.env.DOCKER_HOST && !process.env.DOCKER_HOST.startsWith('unix://')) {
    fail('HECC requires a local Docker daemon; remote Docker would expose plaintext.');
  }
  await docker(['info', '--format', '{{.ServerVersion}}']);
}

async function foreground(args: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: 'inherit' });
    const forward = (signal: NodeJS.Signals): void => { child.kill(signal); };
    const interrupt = (): void => forward('SIGINT'); const terminate = (): void => forward('SIGTERM');
    process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
    child.once('error', () => reject(new HeccError('Could not start Docker.')));
    child.once('close', code => {
      process.off('SIGINT', interrupt); process.off('SIGTERM', terminate); resolve(code ?? 1);
    });
  });
}

export async function buildSandbox(): Promise<void> {
  await checkDocker();
  // A small, separate build context never includes the project, .env, or keys.
  const context = await mkdtemp(path.join(tmpdir(), 'hecc-build-'));
  try {
    await copyFile(path.join(sandboxDirectory, 'Dockerfile'), path.join(context, 'Dockerfile'));
    await copyFile(fileURLToPath(new URL('../scripts/relay.js', import.meta.url)), path.join(context, 'relay.mjs'));
    if (await foreground(['build', '--tag', SANDBOX_IMAGE, context]) !== 0) fail('Sandbox image build failed.');
  } finally { await rm(context, { recursive: true, force: true }); }
}

export interface Subscription {
  authorization: string;
  credentials: string;
  account: unknown;
}

export async function loadSubscription(directory = process.env.CLAUDE_CONFIG_DIR ?? path.join(homedir(), '.claude')): Promise<Subscription> {
  try {
    const file = path.join(directory, '.credentials.json');
    const stat = await lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || stat.mode & 0o077 || stat.size > 256 * 1024) throw new Error();
    const parsed: unknown = JSON.parse(await readFile(file, 'utf8'));
    if (!isRecord(parsed) || !isRecord(parsed.claudeAiOauth)) throw new Error();
    const oauth = parsed.claudeAiOauth;
    if (typeof oauth.accessToken !== 'string' || !oauth.accessToken || /\s/.test(oauth.accessToken) ||
        typeof oauth.expiresAt !== 'number' || oauth.expiresAt <= Date.now()) {
      fail('Claude subscription login is missing or expired. Run claude auth login outside HECC, then retry.');
    }
    const configPath = directory === path.join(homedir(), '.claude') ? path.join(homedir(), '.claude.json') : path.join(directory, '.claude.json');
    let account: unknown;
    try { const config: unknown = JSON.parse(await readFile(configPath, 'utf8')); if (isRecord(config)) account = config.oauthAccount; }
    catch { /* Auth status can work without optional cached account metadata. */ }
    return { authorization: `Bearer ${oauth.accessToken}`, credentials: JSON.stringify({ claudeAiOauth: oauth }), account };
  } catch (error) {
    if (error instanceof HeccError) throw error;
    fail('Cannot read a private Claude subscription login. Run claude auth login outside HECC.');
  }
}

async function nativeClaude(): Promise<string> {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    try {
      const candidate = await realpath(path.join(dir, 'claude'));
      await access(candidate, constants.X_OK);
      const handle = await open(candidate, 'r');
      const bytes = Buffer.alloc(4);
      try { await handle.read(bytes, 0, 4, 0); } finally { await handle.close(); }
      if (bytes.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) return candidate;
      fail('The enforced launcher requires the native Linux Claude binary. Install it with claude install.');
    } catch (error) { if (error instanceof HeccError) throw error; }
  }
  fail('Cannot find the native Claude binary on PATH.');
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
  /** Controlled test injection; never exposed as arbitrary CLI arguments. */
  command?: string[];
}

/** Runs the native client and all descendant tools in a networkless namespace.
 * A separate relay alone can open the host gateway socket. Seccomp denies Unix
 * sockets in the client, including sockets hidden in a writable workspace. */
export async function runSandbox(options: SandboxOptions): Promise<number> {
  const uid = process.getuid!(); const gid = process.getgid!();
  const relay = `hecc-relay-${randomUUID()}`; const client = `hecc-claude-${randomUUID()}`;
  const base = ['--rm', '--pull=never', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
    '--pids-limit=256', '--user', `${uid}:${gid}`, '--log-driver=none'];
  const home = path.join(options.runtime, 'home');
  // Runtime socket directory and credentials are separate mounts. The relay
  // sees neither the workspace nor the client's subscription credential.
  const sockets = path.join(options.runtime, 'sockets');
  await copyFile(path.join(sandboxDirectory, 'seccomp.json'), path.join(options.runtime, 'seccomp.json'));
  try {
    await docker(['run', '-d', '--name', relay, ...base, '--network=none',
      ...mount(sockets, '/run/hecc', true), SANDBOX_IMAGE]);
    // Probe the listening socket inside the isolated network, without contacting
    // the gateway or passing any user text. Retries are bounded by the CLI call.
    await docker(['exec', relay, 'node', '-e',
      "const net=require('node:net');let n=0;function probe(){const s=net.connect(17840,'127.0.0.1',()=>{s.destroy();process.exit(0)});s.on('error',()=>{if(++n>50)process.exit(1);setTimeout(probe,100)})}probe()"]);
    const args = ['run', '--name', client, ...base, '--network', `container:${relay}`,
      '--security-opt', `seccomp=${path.join(options.runtime, 'seccomp.json')}`,
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
      ...mount(options.workspace, '/workspace'), ...mount(home, '/home/hecc'),
      ...mount(options.binary, '/usr/local/bin/claude', true),
      '--workdir=/workspace', '--env=HOME=/home/hecc', '--env=ANTHROPIC_BASE_URL=http://127.0.0.1:17840',
      '--env=CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1', '--env=DISABLE_AUTOUPDATER=1',
      '--env=ENABLE_CLAUDEAI_MCP_SERVERS=false', '--env=CLAUDE_CODE_ATTRIBUTION_HEADER=0',
      '--env=CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1', '--env=TERM=xterm-256color'];
    // The detector's .env is loaded by the host and hidden from Claude's tools.
    try { await lstat(path.join(options.workspace, '.env')); args.push(...mount('/dev/null', '/workspace/.env', true)); }
    catch { /* No dotenv file to mask. */ }
    args.push('-i');
    if (process.stdin.isTTY && process.stdout.isTTY && !options.print) args.push('-t');
    args.push(SANDBOX_IMAGE, ...(options.command ?? ['claude', '--setting-sources', 'project,local', '--strict-mcp-config']));
    if (!options.command) {
      if (options.model) args.push('--model', options.model);
      if (options.print) args.push('--print');
    }
    return await foreground(args);
  } finally {
    // Also kill detached descendants after terminal cancellation/client crashes.
    await docker(['rm', '-f', client]).catch(() => {});
    await docker(['rm', '-f', relay]).catch(() => {});
  }
}

export async function launchClaude(settings: ProviderSettings, key: Buffer, configDir: string,
  options: { model?: string; print?: boolean } = {}): Promise<number> {
  await checkDocker();
  await docker(['image', 'inspect', SANDBOX_IMAGE, '--format', '{{.Id}}']);
  const subscription = await loadSubscription();
  const binary = await nativeClaude();
  const workspace = await realpath(process.cwd());
  const privateDir = await realpath(configDir);
  if (privateDir === workspace || privateDir.startsWith(workspace + path.sep)) fail('The encryption key must be outside the mounted workspace.');
  if (!options.print && (!process.stdin.isTTY || !process.stdout.isTTY)) fail('Use hecc claude --print for piped input.');
  const runtime = await mkdtemp(path.join(tmpdir(), 'hecc-run-'));
  if (runtime.startsWith(workspace + path.sep)) {
    await rm(runtime, { recursive: true, force: true });
    fail('Launch from a project directory that does not contain the temporary runtime directory.');
  }
  const sockets = path.join(runtime, 'sockets'); const home = path.join(runtime, 'home');
  let gateway: Awaited<ReturnType<typeof startGateway>> | undefined;
  try {
    await mkdir(sockets, { mode: 0o700 }); await mkdir(path.join(home, '.claude'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(home, '.claude/.credentials.json'), subscription.credentials, { mode: 0o600 });
    await writeFile(path.join(home, '.claude.json'), JSON.stringify({
      hasCompletedOnboarding: true, oauthAccount: subscription.account,
      autoUpdates: false, installMethod: 'native',
    }), { mode: 0o600 });
    const protector = new RequestProtector(key, (text, signal) => detectSensitive(text, settings.config, settings.env, signal));
    gateway = await startGateway({ protector, authorization: subscription.authorization, socketPath: path.join(sockets, 'gateway.sock') });
    process.stderr.write('hecc: Native Claude is isolated. Model requests are inspected; other network access is blocked.\n');
    return await runSandbox({ workspace, runtime, binary, ...options });
  } finally {
    await gateway?.close();
    await rm(runtime, { recursive: true, force: true });
  }
}
