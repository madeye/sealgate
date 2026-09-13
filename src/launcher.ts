import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir, tmpdir, userInfo } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail, hasErrorCode, SealgateError } from './errors.js';
import { isRecord } from './types.js';

const execute = promisify(execFile);
export const sandboxDirectory = fileURLToPath(new URL('../../sandbox/', import.meta.url));
export const CLAUDE_ARGS = ['--setting-sources', 'project,local', '--strict-mcp-config'];
/** Fixed loopback ports inside the Linux relay network namespace. */
export const RELAY_GATEWAY_PORT = 17840;
export const RELAY_PROXY_PORT = 17841;

/** Environment handed to native Claude. Nothing from the host environment is forwarded. */
export function claudeEnvironment(gatewayUrl: string, proxyUrl?: string): Record<string, string> {
  const env: Record<string, string> = {
    ANTHROPIC_BASE_URL: gatewayUrl, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1',
    ENABLE_CLAUDEAI_MCP_SERVERS: 'false', CLAUDE_CODE_ATTRIBUTION_HEADER: '0', CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS: '1',
  };
  if (proxyUrl) {
    // Claude's own model requests stay on the gateway; only tool traffic may use the proxy.
    for (const name of ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']) env[name] = proxyUrl;
    env.NO_PROXY = '127.0.0.1,localhost'; env.no_proxy = env.NO_PROXY;
  }
  return env;
}

export function foreground(command: string, args: string[], options: { env?: Record<string, string>; cwd?: string } = {}): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', env: options.env, cwd: options.cwd });
    const forward = (signal: NodeJS.Signals): void => { child.kill(signal); };
    const interrupt = (): void => forward('SIGINT'); const terminate = (): void => forward('SIGTERM');
    process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
    child.once('error', () => reject(new SealgateError('Could not start the sandbox process.')));
    child.once('close', code => {
      process.off('SIGINT', interrupt); process.off('SIGTERM', terminate); resolve(code ?? 1);
    });
  });
}

export interface Subscription {
  authorization: string;
  credentials: string;
  account: unknown;
}

async function readKeychain(): Promise<string | undefined> {
  try {
    const { stdout } = await execute('/usr/bin/security', ['find-generic-password', '-s', 'Claude Code-credentials', '-a', userInfo().username, '-w'],
      { timeout: 10_000, maxBuffer: 256 * 1024, env: { PATH: '/usr/bin:/bin' } });
    return stdout.trim() || undefined;
  } catch { return undefined; }
}

export interface SubscriptionOptions {
  /** Test injection: replaces the macOS Keychain read. */
  keychain?: () => Promise<string | undefined>;
}

/** Reads the saved claude.ai login: the private credentials file, or on macOS the
 * default Keychain item when no file exists. Custom config directories use the file only. */
export async function loadSubscription(directory?: string, options: SubscriptionOptions = {}): Promise<Subscription> {
  const defaultDir = path.join(homedir(), '.claude');
  const dir = directory ?? process.env.CLAUDE_CONFIG_DIR ?? defaultDir;
  try {
    let raw: string | undefined;
    const file = path.join(dir, '.credentials.json');
    try {
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || stat.mode & 0o077 || stat.size > 256 * 1024) throw new Error();
      raw = await readFile(file, 'utf8');
    } catch (error) {
      if (!hasErrorCode(error, 'ENOENT')) throw error;
      const keychain = options.keychain ?? (process.platform === 'darwin' && dir === defaultDir ? readKeychain : undefined);
      raw = await keychain?.();
    }
    if (raw === undefined) throw new Error();
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed) || !isRecord(parsed.claudeAiOauth)) throw new Error();
    const oauth = parsed.claudeAiOauth;
    if (typeof oauth.accessToken !== 'string' || !oauth.accessToken || /\s/.test(oauth.accessToken) ||
        typeof oauth.expiresAt !== 'number' || oauth.expiresAt <= Date.now()) {
      fail('Claude subscription login is missing or expired. Run claude auth login outside SEALGATE, then retry.');
    }
    const configPath = dir === defaultDir ? path.join(homedir(), '.claude.json') : path.join(dir, '.claude.json');
    let account: unknown;
    try { const config: unknown = JSON.parse(await readFile(configPath, 'utf8')); if (isRecord(config)) account = config.oauthAccount; }
    catch { /* Auth status can work without optional cached account metadata. */ }
    return { authorization: `Bearer ${oauth.accessToken}`, credentials: JSON.stringify({ claudeAiOauth: oauth }), account };
  } catch (error) {
    if (error instanceof SealgateError) throw error;
    fail('Cannot read a private Claude subscription login. Run claude auth login outside SEALGATE.');
  }
}

export const isElf = (magic: Buffer): boolean => magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
export const isMachO = (magic: Buffer): boolean => [[0xcf, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf], [0xca, 0xfe, 0xba, 0xbe]]
  .some(bytes => magic.equals(Buffer.from(bytes)));

/** Resolves the installed native Claude binary on PATH and checks its executable format. */
export async function findNativeClaude(isNative: (magic: Buffer) => boolean, wrongFormat: string): Promise<string> {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    try {
      const candidate = await realpath(path.join(dir, 'claude'));
      await access(candidate, constants.X_OK);
      const handle = await open(candidate, 'r');
      const bytes = Buffer.alloc(4);
      try { await handle.read(bytes, 0, 4, 0); } finally { await handle.close(); }
      if (isNative(bytes)) return candidate;
      fail(wrongFormat);
    } catch (error) { if (error instanceof SealgateError) throw error; }
  }
  fail('Cannot find the native Claude binary on PATH.');
}

export interface Runtime {
  dir: string;
  home: string;
  sockets: string;
  tmp: string;
}

/** Creates the private per-launch directory: socket dir, temporary Claude home
 * with the login snapshot, and a temporary directory. Removed by the caller. */
export async function prepareRuntime(subscription: Subscription, workspace: string): Promise<Runtime> {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'sealgate-run-')));
  if (dir === workspace || dir.startsWith(workspace + path.sep)) {
    await rm(dir, { recursive: true, force: true });
    fail('Launch from a project directory that does not contain the temporary runtime directory.');
  }
  const home = path.join(dir, 'home'); const sockets = path.join(dir, 'sockets'); const tmp = path.join(dir, 'tmp');
  await mkdir(sockets, { mode: 0o700 }); await mkdir(tmp, { mode: 0o700 });
  await mkdir(path.join(home, '.claude'), { recursive: true, mode: 0o700 });
  await writeFile(path.join(home, '.claude/.credentials.json'), subscription.credentials, { mode: 0o600 });
  const state = JSON.stringify({ hasCompletedOnboarding: true, oauthAccount: subscription.account, autoUpdates: false, installMethod: 'native' });
  // Claude reads this beside HOME by default and inside CLAUDE_CONFIG_DIR when that is set.
  await writeFile(path.join(home, '.claude.json'), state, { mode: 0o600 });
  await writeFile(path.join(home, '.claude/.claude.json'), state, { mode: 0o600 });
  return { dir, home, sockets, tmp };
}
