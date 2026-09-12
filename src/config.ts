import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { DEFAULT_INSTRUCTIONS } from './detection.js';
import { fail, hasErrorCode, HeccError } from './errors.js';
import { isRecord } from './types.js';
import type { Config, Environment, InitOptions } from './types.js';

export function configDirectory(env: Environment = process.env): string {
  const dir = env.HECC_CONFIG_DIR || path.join(env.XDG_CONFIG_HOME || path.join(homedir(), '.config'), 'hecc');
  if (!path.isAbsolute(dir)) fail('HECC_CONFIG_DIR and XDG_CONFIG_HOME must be absolute paths.');
  return dir;
}

export function endpointFor(baseUrl: string): URL {
  let url: URL;
  try { url = new URL(baseUrl); } catch { fail('Configure a valid provider baseUrl.'); }
  const loopback = url.hostname === 'localhost' || url.hostname === '[::1]' ||
    /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) ||
      url.username || url.password || url.search || url.hash) {
    fail('Provider URL must use HTTPS (HTTP is allowed only on loopback), without credentials, query, or fragment.');
  }
  url.pathname = url.pathname.replace(/\/+$/, '') + '/chat/completions';
  return url;
}

export function validateConfig(config: unknown): Config {
  const fields = ['version', 'baseUrl', 'model', 'apiKeyEnv', 'timeoutMs', 'detectionInstructions', 'additionalCategories'];
  if (!isRecord(config) ||
      Object.keys(config).some(key => !fields.includes(key)) || config.version !== 1 ||
      typeof config.baseUrl !== 'string' ||
      typeof config.model !== 'string' || !config.model.trim() || config.model.length > 512 ||
      !(config.apiKeyEnv === null || (typeof config.apiKeyEnv === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(config.apiKeyEnv))) ||
      typeof config.timeoutMs !== 'number' || !Number.isInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 300_000 ||
      typeof config.detectionInstructions !== 'string' || !config.detectionInstructions.trim() || config.detectionInstructions.length > 32_768 ||
      !Array.isArray(config.additionalCategories) || config.additionalCategories.length > 100 ||
      config.additionalCategories.some(value => typeof value !== 'string' || !value.trim() || value.length > 1024)) {
    fail('Invalid configuration; check the documented config.json schema.');
  }
  endpointFor(config.baseUrl);
  return {
    version: config.version,
    baseUrl: config.baseUrl,
    model: config.model,
    apiKeyEnv: config.apiKeyEnv,
    timeoutMs: config.timeoutMs,
    detectionInstructions: config.detectionInstructions,
    additionalCategories: config.additionalCategories,
  };
}

export function makeConfig(options: InitOptions): Config {
  return validateConfig({
    version: 1,
    baseUrl: options.baseUrl,
    model: options.model,
    apiKeyEnv: options.apiKeyEnv === undefined ? 'HECC_API_KEY' : options.apiKeyEnv,
    timeoutMs: options.timeoutMs ?? 30_000,
    detectionInstructions: DEFAULT_INSTRUCTIONS,
    additionalCategories: [],
  });
}

async function exists(file: string): Promise<boolean> {
  try { await lstat(file); return true; } catch (error) {
    if (hasErrorCode(error, 'ENOENT')) return false;
    throw error;
  }
}

async function outsideRepository(dir: string): Promise<void> {
  // Resolve the nearest existing ancestor, including symlinked parent directories.
  let ancestor = path.resolve(dir);
  while (!(await exists(ancestor))) ancestor = path.dirname(ancestor);
  ancestor = await realpath(ancestor);
  while (true) {
    if (await exists(path.join(ancestor, '.git'))) fail('HECC configuration and key must be outside a Git repository.');
    const parent = path.dirname(ancestor);
    if (parent === ancestor) return;
    ancestor = parent;
  }
}

function checkPrivate(stat: Stats, directory = false): void {
  if (process.platform === 'win32') fail('Owner-only key storage requires Linux, macOS, or WSL in this version.');
  if ((directory ? !stat.isDirectory() : !stat.isFile()) ||
      stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 || (!directory && stat.nlink !== 1)) {
    fail('HECC storage must be owned by you, with directory mode 700 and file mode 600, without links.');
  }
}

async function checkDirectory(dir: string): Promise<void> {
  await outsideRepository(dir);
  checkPrivate(await lstat(dir), true);
}

async function readPrivate(file: string, maxBytes: number): Promise<Buffer> {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    checkPrivate(stat);
    if (stat.size > maxBytes) fail('HECC configuration or key file is too large.');
    return await handle.readFile();
  } finally { await handle.close(); }
}

async function writePrivate(file: string, contents: string | Buffer): Promise<void> {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(contents); await handle.sync(); } finally { await handle.close(); }
}

export async function initialize(dir: string, options: InitOptions): Promise<void> {
  const config = makeConfig(options);
  try {
    if (process.platform === 'win32') fail('Owner-only key storage requires Linux, macOS, or WSL in this version.');
    await outsideRepository(dir);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await checkDirectory(dir);
    const configPath = path.join(dir, 'config.json');
    const keyPath = path.join(dir, 'key');
    if (await exists(configPath)) fail('Already initialized; edit config.json to change provider settings. The key was preserved.');
    // Preserve an existing key after an interrupted initialization. Never rotate it implicitly.
    if (await exists(keyPath)) await loadKey(dir);
    else await writePrivate(keyPath, randomBytes(32));
    await writePrivate(configPath, JSON.stringify(config, null, 2) + '\n');
  } catch (error) {
    if (error instanceof HeccError) throw error;
    fail('Initialization failed; check the private configuration directory. Existing files were not overwritten.');
  }
}

export async function loadConfig(dir: string): Promise<Config> {
  try {
    await checkDirectory(dir);
    const bytes = await readPrivate(path.join(dir, 'config.json'), 256 * 1024);
    return validateConfig(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  } catch (error) {
    if (error instanceof HeccError) throw error;
    fail('Cannot read configuration; run hecc init or check config.json and its permissions.');
  }
}

export async function loadKey(dir: string): Promise<Buffer> {
  try {
    await checkDirectory(dir);
    const key = await readPrivate(path.join(dir, 'key'), 32);
    if (key.length !== 32) fail('Encryption key must contain exactly 32 bytes.');
    return key;
  } catch (error) {
    if (error instanceof HeccError) throw error;
    fail('Cannot read encryption key; check initialization and owner-only permissions.');
  }
}
