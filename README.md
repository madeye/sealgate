# hecc

Encrypt sensitive spans locally before pasting a prompt into Claude Code. `hecc`
sends your original text to a **trusted detection provider** that you configure,
then uses a local AES-256-GCM key to replace the detected spans with ciphertext.
`hecc chat` provides a terminal interface that protects each prompt and sends it
to Claude Code automatically. The companion plugin adds a session reminder.

This is conventional authenticated encryption, **not homomorphic inference**.
Claude can use the surrounding text but cannot understand encrypted values.

```mermaid
flowchart LR
    U[Your prompt] --> C[hecc protect]
    C -->|Original text| P[Trusted LLM or local vLLM]
    P -->|Exact sensitive substrings| C
    K[Local encryption key] --> C
    C -->|Text with encrypted spans| O[Protected output]
    O -->|hecc chat sends, or you paste| A[Claude Code]
    O --> D[hecc decrypt locally]
    K --> D
    D --> R[Restored text in your terminal]
```

See [how it works](docs/how-it-works.md) for the detection, encryption, and
decryption steps, and [the security model](docs/security.md) for trust boundaries
and limitations. The instructions below cover installation and configuration.

## Install

Requires Node.js 22 or later on Linux, macOS, or WSL. The project is written in
TypeScript and compiles to Node.js ES modules in `dist/`. TypeScript and Node type
definitions are development dependencies; the installed CLI has no runtime npm
dependencies. From this checkout:

```sh
git clone https://github.com/madeye/hecc.git
cd hecc
npm ci
npm install --global .
hecc --help
claude --plugin-dir /absolute/path/to/hecc
```

`npm ci` installs the locked development dependencies and builds the project.
You can also use `node /absolute/path/to/hecc/dist/bin/hecc.js` after building,
without installing the CLI. The plugin is loaded for Claude sessions launched
with `--plugin-dir`; its hook also runs compiled code from `dist/`.
Installing the npm CLI alone does not enable the Claude plugin. See Claude's
[plugin reference](https://code.claude.com/docs/en/plugins-reference) for loading
and distributing plugins.

## Configure a trusted provider

Choose a provider that you trust to receive the full original prompt. It must
support the OpenAI-compatible `POST /chat/completions` API and JSON object output.
There is no default remote provider or fallback.

```sh
hecc init --base-url https://your-trusted-provider.example/v1 --model your-detector-model
```

The `.example` URL is a placeholder; substitute your actual trusted service.
Initialize with a model identifier supported by that service. Supply its API key
through the `HECC_API_KEY` environment variable, preferably using a secret manager.
For an interactive Bash session, this avoids placing the key in shell history:

```sh
read -rsp 'Trusted provider API key: ' HECC_API_KEY
export HECC_API_KEY
printf '\n'
```

To use another environment variable, pass `--api-key-env PRIVATE_LLM_API_KEY` to
`init`. Use `--no-api-key` for an explicitly unauthenticated provider, for example:

```sh
hecc init --base-url http://127.0.0.1:8000/v1 --model local-detector --no-api-key
```

HTTPS is required except for loopback HTTP (`localhost`, `127.0.0.0/8`, or `::1`).
URL credentials, query strings, fragments, and HTTP redirects are rejected.
The base path is preserved and `/chat/completions` appended, so include `/v1` if
your provider requires it. HTTP errors, refusals, truncated responses, unsupported
JSON mode, and malformed answers fail without printing a protected prompt.

Initialization creates these files outside Git repositories:

- `~/.config/hecc/config.json`: provider and detection settings, mode `600`.
- `~/.config/hecc/key`: 32 random binary bytes, mode `600`.
- The containing `hecc` directory has mode `700`.

`XDG_CONFIG_HOME` changes the configuration parent; `HECC_CONFIG_DIR` overrides the
whole directory. Both must be absolute paths. Keep it outside source repositories
and shared directories. Unsafe permissions, linked storage files, and a symlink
for the `hecc` directory are rejected. Native Windows permissions are unsupported;
use WSL and its Linux filesystem.

Edit the private `config.json` to change settings. Its complete schema is:

```json
{
  "version": 1,
  "baseUrl": "https://your-trusted-provider.example/v1",
  "model": "your-detector-model",
  "apiKeyEnv": "HECC_API_KEY",
  "timeoutMs": 30000,
  "detectionInstructions": "Detect credentials, personal identifiers, contact details, financial information, and explicitly marked confidential content.",
  "additionalCategories": ["Unreleased project names", "Internal customer identifiers"]
}
```

`init` writes more detailed default detection instructions covering those five
categories. `additionalCategories` extends them; editing `detectionInstructions`
replaces the category instructions. Use `apiKeyEnv: null` for no Authorization
header. Never place an API key itself in this file. The timeout is an integer from
1 to 300000 milliseconds and covers the entire HTTP response; set its initial
value with `--timeout-ms`. Unknown configuration fields are rejected.

### Local vLLM with `.env`

`hecc protect` also reads `.env` from your current working directory. For a local
vLLM gateway, use the following settings (substitute your served model and key):

```dotenv
HECC_BASE_URL=http://127.0.0.1:8080/v1
HECC_MODEL=qwen3.8-27b
HECC_API_KEY_ENV=HECC_API_KEY
HECC_API_KEY=your-local-gateway-key
HECC_TIMEOUT_MS=120000
```

Set file permissions with `chmod 600 .env`. This repository ignores `.env` files
and excludes them from the npm package. Run `hecc protect` from the directory
containing this file; no shell `source` command is required. Exported environment
variables override `.env`, which overrides the corresponding `config.json`
provider settings. `HECC_API_KEY_ENV=` explicitly disables authentication.

Initialize the local key with `hecc init` as described above before first use.
The `.env` file only supplies provider settings and the named API credential;
it cannot relocate the encryption key or change detection instructions. All
other variables are ignored, and the file is parsed as data without executing
shell code. Decryption does not read `.env` or contact vLLM. Keep real credentials
out of prompts and source control.

## Protect a prompt

### Automatic terminal chat

After initializing `hecc` and configuring your trusted detector, run:

```sh
hecc chat
```

This opens a full-screen terminal interface. Enter a prompt, then press **Ctrl-S**
to detect and encrypt sensitive spans and send the protected result to Claude
Code. Replies stream into the conversation. Follow-up prompts go through the same
protection step and continue the wrapper's own Claude session.

| Key or command | Action |
| --- | --- |
| Ctrl-S | Protect and send the current draft |
| Enter | Insert a newline |
| Left / Right, Home / End | Move within the draft |
| Ctrl-U | Clear the draft |
| Ctrl-C | Cancel the current request; exit when idle |
| Ctrl-D | Exit, canceling an active request |
| Page Up / Page Down | Scroll the conversation |
| `/new`, then Ctrl-S | Start a fresh conversation |
| `/quit`, then Ctrl-S | Exit |

Pasting multiline text does not submit it. The conversation displays encrypted
spans as `[encrypted]` for readability; the full ciphertext markers are sent to
Claude. Plaintext is visible in the local draft editor. `hecc` keeps no chat log
on disk and does not decrypt replies. Claude Code may persist the protected
conversation according to its own settings.

The `claude` command must be installed and signed in (`claude auth status`). If
Claude reports an expired token, run `claude auth login` outside the wrapper. Use
`hecc chat --model MODEL` to select Claude's model; the detector model stays in
your provider settings. `.env` is loaded from the directory where you start the
wrapper. Run it in a trusted project directory, since Claude Code loads its normal
project context and configuration.

The wrapper uses Claude's print mode with `dontAsk` permissions. Existing allowed
tools can run, but tool calls requiring a new approval are denied. There is no
interactive permission dialog, slash-command forwarding, or file/image picker in
this version. The wrapper never enables permission bypass. Files, tool results,
and existing project context are not processed by the detector.

Detection failures keep the local draft for editing and never start Claude. A
canceled or failed Claude turn resets the wrapper's session to avoid silently
continuing an incomplete conversation. See [terminal chat internals](docs/how-it-works.md#terminal-chat)
for streaming, session handling, and credential isolation.

### Manual preprocessing

Run this in **your own terminal, outside Claude's tools**:

```sh
hecc protect
```

Type or paste multiple lines, then press Ctrl-D on an empty line to finish stdin.
The terminal echoes what you type; its scrollback may retain plaintext. Input is
read by `hecc`, so it is not a shell command or shell history entry. You can also
redirect an existing UTF-8 file:

```sh
hecc protect < private-prompt.txt
```

Paste the successful stdout into Claude Code. A result might look like
`Draft a reply to [[HECC:v1:...]].` (the ellipsis is illustrative, not valid
ciphertext). Diagnostics and the terminal-entry reminder go to stderr; stdout
contains only the complete result with no added newline. Check the exit code when
scripting: a successful empty input also produces empty stdout. Do not fall back
to sending the original prompt if the command fails.

The detector returns `{"sensitive_substrings":["exact text"]}`. `hecc` validates
every entry against the original prompt, replaces every occurrence, and merges
overlapping matches. Unicode and line breaks must match exactly; nonmatching
entries cause failure. Surrounding text, whitespace, and trailing newlines are
preserved. An empty detection list passes the original text through unchanged.
Protection accepts up to 1 MiB of UTF-8 input; responses are capped at 4 MiB,
lists at 10000 entries, and occurrences at 100000.

Each occurrence receives fresh randomized ciphertext, including repeated values.
The prefix `[[HECC:` is reserved. Prompts already containing that prefix are
rejected; always protect the original plaintext rather than protecting an output
again.

## Decrypt locally and back up the key

```sh
hecc decrypt < protected-prompt.txt
```

Or run `hecc decrypt`, paste the protected text, and finish with Ctrl-D. Decryption
requires only the local key; it makes no network request and does not require
provider configuration or an API key. It accepts up to 16 MiB of UTF-8 input and
restores all recognized markers while preserving surrounding text. A malformed,
unsupported, or unauthenticated marker fails the entire operation without
printing partial plaintext. Text without markers passes through unchanged.

Back up the binary `key` file in a secure encrypted backup before relying on it.
Anyone with the key can decrypt your markers; losing it makes old ciphertext
unrecoverable. `hecc init` refuses to overwrite existing configuration and never
implicitly rotates a key. To restore a backup, place it at the same `key` path
with mode `600` in a directory with mode `700`, both owned by you. To use a new
key, initialize a separate private configuration directory and retain the old
key for old ciphertext. There is no automatic rotation or key identifier in v1.

Never ask Claude to run `hecc decrypt` or read your key. The plugin exposes no
decryption tool and never automatically returns plaintext to Claude. Its reminder
is guidance, not a sandbox: another process or Claude tool running as your OS user
may still access files that user can read. Use OS isolation if that threat is in
scope. Keep plaintext output, clipboard contents, and backups private.

## Format and limits

Markers are `[[HECC:v1:PAYLOAD]]`. `PAYLOAD` is canonical, unpadded base64url encoding
of a 12-byte random nonce, a 16-byte GCM authentication tag, and the ciphertext.
AES-256-GCM uses the 32-byte local key and authenticates the constant `hecc:v1`
as additional authenticated data. The key is never included in a provider request
or a marker. Each span is authenticated independently; surrounding text, marker
position, deletion, and rearrangement are not authenticated. Changing the marker
prefix so it is no longer recognizable can make it ordinary text to the decoder.

Only prompts explicitly passed through `hecc protect` are covered. Direct Claude
input, files, tool results, existing history, and other provider traffic are
outside this version. Claude's
[hook decision-control documentation](https://code.claude.com/docs/en/hooks#decision-control)
specifies that `UserPromptSubmit` cannot replace a submitted prompt, so the plugin
uses only a `SessionStart` reminder. Automatic submission happens in the `hecc
chat` wrapper before Claude is invoked. No gateway or Claude authentication
changes are required.

Detection is probabilistic: a provider can miss secrets, misunderstand your
categories, or follow malicious instructions embedded in input. Output validation
checks the format and exact matches, not detection completeness. The trusted
provider sees plaintext and its own retention policy applies. Encryption hides
the matched content from Claude but leaks approximate span lengths and positions;
surrounding context may also reveal information. There is no guarantee that every
secret is removed. JavaScript strings and terminal buffers cannot be reliably
zeroized; this is not protection against a compromised local machine.

Encrypted values reduce answer quality for tasks that depend on those values.
For example, Claude can draft an email around an encrypted address but cannot
validate the address, calculate with encrypted financial amounts, or compare two
independently encrypted values. Prefer placeholders or synthetic data when the
task requires interpreting the hidden values.

## Verify

```sh
npm run typecheck
npm test
npm run validate:plugin
npm pack --dry-run
```

Tests use synthetic data and local mock HTTP providers. They cover exact matching,
overlap, Unicode, multiline input, no matches, key permissions, encryption
randomness, tampering, request construction, redirects, timeouts, invalid provider
responses, failure output, offline decryption, and the session hook. Plugin
validation requires the Claude Code CLI. No live provider is needed for tests.
Chat tests also use a mock Claude process to check protected stdin, session
continuity, credential isolation, streaming, cancellation, and failure handling.

Source files live in `src/`, `bin/`, `scripts/`, and `test/`. Strict TypeScript
checking covers all four directories. Run `npm run build` after editing source;
`npm test` builds and runs the compiled tests with Node's built-in test runner.
Relative imports use `.js` extensions to match the compiled Node.js modules.
`dist/` is generated and Git-ignored. `npm pack` builds automatically and includes
only the compiled runtime, plugin files, and documentation, excluding tests,
development sources, `.env`, and local keys.

## License

[MIT](LICENSE). Copyright (c) 2026 Max Lv.
