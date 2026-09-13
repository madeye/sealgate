import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { parseEnv } from 'node:util';
import { validateConfig } from './config.js';
import { fail, hasErrorCode, SealgateError } from './errors.js';
import type { Config, Environment, ProviderSettings } from './types.js';

async function readDotEnv(cwd: string): Promise<Environment> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path.join(cwd, '.env'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) {
      fail('.env must be an unlinked regular file owned by you with mode 600.');
    }
    if (stat.size > 256 * 1024) fail('.env exceeds the configuration size limit.');
    return parseEnv(new TextDecoder('utf-8', { fatal: true }).decode(await handle.readFile()));
  } catch (error) {
    if (hasErrorCode(error, 'ENOENT')) return {};
    if (error instanceof SealgateError) throw error;
    return fail('Cannot read .env; check its format, type, and owner-only permissions.');
  } finally {
    await handle?.close();
  }
}

// Read only provider settings and the configured credential. Never execute the
// file, mutate process.env, or allow it to relocate the local encryption key.
export async function providerSettings(
  config: Config,
  { cwd = process.cwd(), env = process.env }: { cwd?: string; env?: Environment } = {},
): Promise<ProviderSettings> {
  const file = await readDotEnv(cwd);
  const value = (name: string): string | undefined => env[name] ?? file[name];
  const effective: Record<string, unknown> = { ...config };
  for (const [name, field] of [
    ['SEALGATE_BASE_URL', 'baseUrl'], ['SEALGATE_MODEL', 'model'],
    ['SEALGATE_API_KEY_ENV', 'apiKeyEnv'], ['SEALGATE_TIMEOUT_MS', 'timeoutMs'],
  ]) {
    const override = value(name);
    if (override !== undefined) {
      effective[field] = field === 'timeoutMs' ? Number(override)
        : field === 'apiKeyEnv' && override === '' ? null : override;
    }
  }
  const thinking = value('SEALGATE_ENABLE_THINKING');
  if (thinking !== undefined) {
    if (thinking !== 'true' && thinking !== 'false') fail('SEALGATE_ENABLE_THINKING must be true or false.');
    effective.enableThinking = thinking === 'true';
  }
  const validated = validateConfig(effective);
  return {
    config: validated,
    env: validated.apiKeyEnv === null ? {} : { [validated.apiKeyEnv]: value(validated.apiKeyEnv) },
  };
}
