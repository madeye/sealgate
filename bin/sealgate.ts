#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { configDirectory, initialize, loadConfig, loadKey } from '../src/config.js';
import { protectText, decryptText, validatePrompt } from '../src/crypto.js';
import { detectSensitive } from '../src/provider.js';
import { providerSettings } from '../src/env.js';
import { fail, SealgateError } from '../src/errors.js';
import { ProtectedChat } from '../src/chat.js';
import { runTui } from '../src/tui.js';
import { buildSandbox, launchClaude } from '../src/sandbox.js';

const HELP = `Usage:
  sealgate init --base-url URL --model MODEL [--api-key-env NAME | --no-api-key] [--timeout-ms N]
  sealgate protect < prompt.txt
  sealgate decrypt < protected.txt
  sealgate chat [--model CLAUDE_MODEL]
  sealgate sandbox-build
  sealgate claude [--model CLAUDE_MODEL] [--print]

claude runs the native Claude interface inside a Docker network sandbox, protecting
complete model requests with the local gateway. Run sandbox-build once first.
Uses your saved subscription login; sign in with claude auth login outside SEALGATE.
Other network traffic and opaque uploads are blocked. Requires native Linux Claude.

chat opens a protected terminal conversation with Claude Code. Ctrl-S sends,
Enter adds a line, Ctrl-C cancels the active turn or exits when idle.

protect and decrypt accept UTF-8 text only through stdin. In a terminal, enter
multiple lines and finish with Ctrl-D (EOF). Input is echoed by your terminal.
Only the result is written to stdout, with no added newline. Diagnostics use stderr.

Configuration: SEALGATE_CONFIG_DIR, otherwise XDG_CONFIG_HOME/sealgate or ~/.config/sealgate.
init creates a private config.json and a local key outside Git repositories.
Default API-key variable: SEALGATE_API_KEY. --no-api-key is for unauthenticated providers.
Edit config.json to customize detection instructions and additionalCategories.
protect loads provider settings and the API credential from .env in the current
directory (mode 600). Exported environment variables take precedence over .env.
The trusted provider receives the original prompt; detection can miss secrets.
Decrypt only in your own terminal, never through Claude's tools.
`;

async function readInput(limit: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > limit) fail('Input exceeds the size limit; no output was produced.');
    chunks.push(chunk);
  }
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)); }
  catch { fail('Input must be valid UTF-8 text.'); }
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(HELP);
    return;
  }
  if (command === 'sandbox-build') {
    if (args.length) fail('sandbox-build accepts no arguments.');
    await buildSandbox(); return;
  }
  if (!['init', 'protect', 'decrypt', 'chat', 'claude'].includes(command)) fail('Expected a SEALGATE command. Use sealgate --help.');
  const dir = configDirectory();
  if (command === 'claude') {
    let values;
    try { ({ values } = parseArgs({ args, options: { model: { type: 'string' }, print: { type: 'boolean' } }, allowPositionals: false, strict: true })); }
    catch { fail('Use sealgate claude [--model CLAUDE_MODEL] [--print]. Prompts are accepted through the terminal or stdin only.'); }
    if (values.model !== undefined && !/^[a-zA-Z0-9._:-]{1,128}$/.test(values.model)) fail('Invalid Claude model.');
    const settings = await providerSettings(await loadConfig(dir));
    const key = await loadKey(dir);
    try { process.exitCode = await launchClaude(settings, key, dir, values); }
    finally { key.fill(0); }
    return;
  }
  if (command === 'chat') {
    let values;
    try { ({ values } = parseArgs({ args, options: { model: { type: 'string' } }, allowPositionals: false, strict: true })); }
    catch { fail('Invalid chat options. Use sealgate chat [--model CLAUDE_MODEL].'); }
    if (values.model !== undefined && !values.model.trim()) fail('Claude model must not be empty.');
    if (!process.stdin.isTTY || !process.stdout.isTTY) fail('sealgate chat requires an interactive terminal. Use sealgate protect for piped input.');
    const settings = await providerSettings(await loadConfig(dir));
    const key = await loadKey(dir);
    try { await runTui(new ProtectedChat(settings, key, { model: values.model })); }
    finally { key.fill(0); }
    return;
  }
  if (command === 'init') {
    let values;
    try {
      ({ values } = parseArgs({ args, options: {
        'base-url': { type: 'string' }, model: { type: 'string' },
        'api-key-env': { type: 'string' }, 'no-api-key': { type: 'boolean' },
        'timeout-ms': { type: 'string' },
      }, allowPositionals: false, strict: true }));
    } catch { fail('Invalid init options. Use sealgate --help.'); }
    if (!values['base-url'] || !values.model) fail('init requires --base-url and --model. Use sealgate --help.');
    if (values['no-api-key'] && values['api-key-env']) fail('Choose --api-key-env or --no-api-key.');
    await initialize(dir, {
      baseUrl: values['base-url'], model: values.model,
      apiKeyEnv: values['no-api-key'] ? null : values['api-key-env'],
      timeoutMs: values['timeout-ms'] === undefined ? undefined : Number(values['timeout-ms']),
    });
    process.stderr.write('sealgate: Initialized private config.json and key. Back up the key securely before use.\n');
    return;
  }
  if (args.length) fail('protect and decrypt accept no arguments; supply text through stdin.');
  // Validate local storage before accepting plaintext or making a network request.
  const settings = command === 'protect' ? await providerSettings(await loadConfig(dir)) : undefined;
  const key = await loadKey(dir);
  try {
    if (process.stdin.isTTY) process.stderr.write('sealgate: Enter text; finish with Ctrl-D on an empty line. Terminal echo is enabled.\n');
    const input = await readInput(command === 'protect' ? 1024 * 1024 : 16 * 1024 * 1024);
    let output: string;
    if (settings) {
      validatePrompt(input);
      output = protectText(input, await detectSensitive(input, settings.config, settings.env), key);
    } else output = decryptText(input, key);
    // Buffer the complete result: a later invalid span/marker must not leak an earlier result.
    process.stdout.write(output);
  } finally { key.fill(0); }
}

process.stdout.on('error', () => {
  process.stderr.write('sealgate: Cannot write output.\n');
  process.exitCode = 1;
});

main().catch(error => {
  process.stderr.write(`sealgate: ${error instanceof SealgateError ? error.message : 'Operation failed; no output was produced.'}\n`);
  process.exitCode = 1;
});
