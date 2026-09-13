import { access, lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir, tmpdir, userInfo } from 'node:os';
import path from 'node:path';
import { fail } from './errors.js';
import { CLAUDE_ARGS, claudeEnvironment, foreground, sandboxDirectory } from './launcher.js';
import type { Runtime } from './launcher.js';

export const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const EXTRA_MARKER = ';; @@EXTRA_RULES@@';

export async function checkSeatbelt(): Promise<void> {
  if (process.platform !== 'darwin' || !['arm64', 'x64'].includes(process.arch)) fail('The enforced launcher requires macOS ARM64/x86-64 or Linux with Docker.');
  try { await access(SANDBOX_EXEC, constants.X_OK); }
  catch { fail('macOS sandbox-exec is unavailable; SEALGATE will not run Claude unconfined.'); }
}

export interface SeatbeltOptions {
  workspace: string;
  runtime: Runtime;
  binary: string;
  keyDir: string;
  /** Extra read-only host paths from config `sandboxReadPaths`. */
  readPaths: string[];
  gatewayPort: number;
  proxyPort?: number;
  model?: string;
  print?: boolean;
  /** Controlled test injection; never exposed as arbitrary CLI arguments. */
  command?: string[];
}

function checkParam(value: string): string {
  if (!path.isAbsolute(value) || /[\x00-\x1f\x7f]/.test(value)) fail('Sandbox paths must be absolute without control characters.');
  return value;
}

function checkPort(port: number): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail('Invalid sandbox port.');
  return port;
}

/** Host-specific values reach the profile only as sandbox-exec -D parameters. */
export async function seatbeltParams(options: SeatbeltOptions): Promise<Record<string, string>> {
  const home = await realpath(homedir());
  const workspace = await realpath(options.workspace);
  if (workspace === home || home.startsWith(workspace + path.sep)) fail('Launch from a project directory, not your home directory or one of its parents.');
  const temp = await realpath(tmpdir());
  const perUser = /^\/private\/var\/folders\/[^/]+\/[^/]+\/T$/.test(temp) ? path.dirname(temp) : temp;
  const params: Record<string, string> = {
    WORKSPACE: workspace, RUNTIME: await realpath(options.runtime.dir), BIN: await realpath(options.binary),
    KEYDIR: await realpath(options.keyDir), USER_FOLDERS: perUser, TEMP: temp,
  };
  const claudeDir = path.join(home, '.claude');
  if (options.readPaths.length > 32) fail('Too many sandboxReadPaths entries.');
  for (const [index, entry] of options.readPaths.entries()) {
    let resolved: string;
    try { await lstat(entry); resolved = await realpath(entry); } catch { fail('A sandboxReadPaths entry does not exist.'); }
    for (const forbidden of [home, params.KEYDIR, claudeDir]) {
      if (resolved === forbidden || forbidden.startsWith(resolved + path.sep)) fail('sandboxReadPaths must not expose your home directory, the key directory, or ~/.claude.');
    }
    params[`READ${index}`] = resolved;
  }
  for (const value of Object.values(params)) checkParam(value);
  return params;
}

/** Rules that vary per launch. They reference parameters or validated numbers only. */
export function extraRules(params: Record<string, string>, gatewayPort: number, proxyPort?: number): string {
  const lines = [`(allow network-outbound (remote ip "localhost:${checkPort(gatewayPort)}"))`];
  if (proxyPort !== undefined) lines.push(`(allow network-outbound (remote ip "localhost:${checkPort(proxyPort)}"))`);
  for (const name of Object.keys(params).filter(key => /^READ\d+$/.test(key))) lines.push(`(allow file-read* (subpath (param "${name}")))`);
  // Xcode command-line shims consult a per-user cache; without it every git/python call spawns xcodebuild.
  if (/^[A-Za-z0-9_/]+$/.test(params.TEMP)) lines.push(`(allow file-read* file-write* (regex #"^${params.TEMP}/xcrun_db"))`);
  return lines.join('\n');
}

export async function buildProfile(params: Record<string, string>, gatewayPort: number, proxyPort?: number): Promise<string> {
  const template = await readFile(path.join(sandboxDirectory, 'profile.sb'), 'utf8');
  if (!template.includes(EXTRA_MARKER)) fail('The sandbox profile template is damaged.');
  return template.replace(EXTRA_MARKER, extraRules(params, gatewayPort, proxyPort));
}

function searchPath(params: Record<string, string>): string {
  const entries = ['/opt/homebrew/bin', '/opt/homebrew/sbin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'];
  for (const [name, value] of Object.entries(params)) if (/^READ\d+$/.test(name)) entries.push(path.join(value, 'bin'));
  return entries.join(':');
}

/** Runs native Claude under a Seatbelt profile whose only network route is the
 * host gateway (plus the proxy forwarder when explicitly enabled). */
export async function runSeatbelt(options: SeatbeltOptions): Promise<number> {
  const params = await seatbeltParams(options);
  const profile = path.join(options.runtime.dir, 'profile.sb');
  await writeFile(profile, await buildProfile(params, options.gatewayPort, options.proxyPort), { mode: 0o600 });
  const args = ['-f', profile];
  for (const [name, value] of Object.entries(params)) args.push('-D', `${name}=${value}`);
  args.push('--', ...(options.command ?? [options.binary, ...CLAUDE_ARGS]));
  if (!options.command) {
    if (options.model) args.push('--model', options.model);
    if (options.print) args.push('--print');
  }
  const user = userInfo().username;
  const env: Record<string, string> = {
    PATH: searchPath(params), HOME: options.runtime.home, CLAUDE_CONFIG_DIR: path.join(options.runtime.home, '.claude'),
    TMPDIR: options.runtime.tmp, TERM: process.env.TERM ?? 'xterm-256color', LANG: process.env.LANG ?? 'en_US.UTF-8',
    SHELL: '/bin/zsh', USER: user, LOGNAME: user,
    ...claudeEnvironment(`http://127.0.0.1:${options.gatewayPort}`, options.proxyPort === undefined ? undefined : `http://127.0.0.1:${options.proxyPort}`),
  };
  for (const name of ['COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION']) { const value = process.env[name]; if (value) env[name] = value; }
  return foreground(SANDBOX_EXEC, args, { env, cwd: params.WORKSPACE });
}
