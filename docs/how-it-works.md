# How hecc works

`hecc` separates sensitive-text detection from cryptography. A trusted model
identifies which parts of a prompt should be hidden. The CLI encrypts those parts
with a key stored on your machine. Claude Code receives the protected output,
submitted automatically by `hecc chat` or pasted manually by you.

The project is written in TypeScript, compiled into Node.js ES modules, and uses
Node's built-in cryptography, HTTP client, and test runner. It has no runtime npm
dependencies.

## Commands

| Command | Input | Network use | Result |
| --- | --- | --- | --- |
| `hecc init` | Provider options | None | Creates private configuration and a random local key |
| `hecc protect` | Original UTF-8 text on stdin | Sends original text to the configured trusted provider | Prints text with detected spans encrypted |
| `hecc decrypt` | Protected UTF-8 text on stdin | None | Restores recognized ciphertext markers locally |
| `hecc chat` | Prompts in a terminal editor | Detector, then Claude Code | Streams replies in a protected conversation |

Protection and decryption accept multiline terminal input ending at EOF, or a file
redirected to stdin. They reject prompt text in command-line arguments. A complete
result goes to stdout without an added newline; diagnostics go to stderr.

## Initialization and provider settings

Initialization generates a 32-byte key using the operating system's cryptographic
random source. By default, the binary key and `config.json` live in
`~/.config/hecc/`. The directory is mode `700`; files are mode `600`. The CLI checks
ownership and permissions when loading them and rejects storage within Git
repositories. Initialization never implicitly rotates an existing key.

The configuration stores the provider base URL, model, credential environment
variable name, timeout, detection instructions, and additional sensitive
categories. `hecc protect` can override provider settings using `.env` in its
current working directory. Exported environment variables take precedence over
`.env`, which takes precedence over `config.json`.

The `.env` file is parsed as data and must be a private regular file. Only provider
settings and the configured credential are read; shell commands are not executed,
and a `.env` setting cannot move the encryption key. See the
[configuration instructions](../README.md#configure-a-trusted-provider) and
[local vLLM example](../README.md#local-vllm-with-env).

## Detection

The CLI sends a nonstreaming `POST` request to the configured base URL with
`/chat/completions` appended. The request contains the model name, a system message
with detection rules, and a user message containing the original prompt. It asks
for JSON object output:

```json
{
  "sensitive_substrings": ["alex@example.test", "synthetic-password"]
}
```

The provider API credential is sent as a Bearer header when configured. The local
encryption key is never included. HTTPS is required for remote endpoints;
loopback endpoints may use HTTP. Redirects are rejected. The configured timeout
covers both waiting for headers and reading the response body.

Default instructions cover credentials, personal identifiers, contact details,
financial information, and explicitly marked confidential content. A local vLLM
service serves the same role as any other compatible trusted detector. It does
not encrypt or decrypt the spans.

## Validating and locating spans

The response must contain one complete assistant answer with valid JSON. The CLI
rejects HTTP errors, refusals, truncated output, unexpected tool calls, and
malformed results. The detection object must have exactly one field,
`sensitive_substrings`, containing nonempty strings found exactly in the input.
Unicode, whitespace, and line breaks must match without normalization.

Each distinct substring is located at every occurrence, including occurrences
that overlap. Ranges are sorted and overlapping ranges are merged. For example:

```text
Input:       x ababa y
Detection:   ["aba", "bab"]
Merged span:   ababa
```

This avoids leaving a portion of an overlapping sensitive value exposed. Adjacent
spans can remain separate. Repeated values receive independent ciphertext. An
empty detection list preserves the original input exactly.

Validation confirms the detector returned usable spans. It cannot establish that
the detector found every secret. See [detection limits](security.md#detection-is-not-a-guarantee).

## Encrypting the matched text

For every merged range, the CLI creates a fresh 12-byte random nonce and encrypts
the exact UTF-8 bytes with AES-256-GCM. It authenticates `hecc:v1` as additional
authenticated data and obtains a 16-byte authentication tag.

The resulting marker has this format:

```text
[[HECC:v1:PAYLOAD]]

PAYLOAD = base64url(nonce || authentication tag || ciphertext)
```

Base64url is canonical and unpadded. The version identifies this encoding and
cryptographic construction. A fresh nonce means identical plaintext generally
produces different markers, even with the same key.

For example, a synthetic prompt could be transformed as follows. The ellipsis
below is illustrative, not a valid ciphertext payload:

```text
Original:  Draft a reply to alex@example.test.
Protected: Draft a reply to [[HECC:v1:...]].
```

The CLI assembles the entire output before printing it. If a later detection entry
or encryption operation fails, it emits no partial prompt. Text outside matched
ranges remains unchanged.

## Decryption and authentication

`hecc decrypt` loads only the local key. It does not load the provider's `.env`
settings or contact a model. It finds each reserved `[[HECC:` marker, checks the
version and encoding, extracts the nonce and tag, and authenticates the ciphertext
before restoring UTF-8 text.

An incorrect key or altered ciphertext causes failure. The entire result is
buffered, so a later invalid marker prevents any earlier plaintext from being
printed. Text without recognized markers passes through unchanged. The original
prompt must not contain the reserved `[[HECC:` prefix; protection rejects it to
avoid confusing ordinary text with ciphertext.

Authentication applies to individual spans. It does not authenticate surrounding
text, marker positions, or the completeness of a document.

## Claude Code integration

The plugin runs a small `SessionStart` hook that reminds the user to preprocess
sensitive prompts in a separate terminal. It also tells Claude to treat markers
as opaque, use the surrounding text, and explain when hidden values prevent an
answer. The hook does not read the original prompt, configuration, or key.

Claude's [hook decision-control reference](https://code.claude.com/docs/en/hooks#decision-control)
states that `UserPromptSubmit` cannot replace a submitted prompt. Consequently,
automatic submission uses a separate terminal wrapper. Manual preprocessing and
pasting are also supported. The plugin provides no decryption
tool and never automatically restores plaintext into Claude's context.

## Terminal chat

`hecc chat` runs a full-screen terminal editor using Node's terminal and readline
primitives. Enter inserts newlines; Ctrl-S submits the draft. Pasted text stays in
the editor until submitted. The UI uses the terminal's alternate screen and
restores normal input and display settings when it exits.

On submission, the wrapper passes the draft through the same detector, span
validation, and local encryption as `hecc protect`. It launches Claude only after
that step succeeds. The original draft is then removed from the editor, and the
conversation displays a protected version with `[encrypted]` labels. This is a
display abbreviation; the full ciphertext is sent to Claude through stdin.

The wrapper invokes the installed `claude` binary directly, without a shell,
using print mode and streamed JSON output. It displays assistant text deltas and
checks for a successful final result. Raw stderr and malformed response bodies
are not shown. Terminal control characters in text are removed before rendering.
The [Claude programmatic usage guide](https://code.claude.com/docs/en/headless)
describes the underlying streaming protocol and session controls.

Each wrapper conversation starts with a fresh UUID. Later turns resume only
that session, never the most recent unrelated conversation. `/new` creates a
fresh session. Detection errors retain the current session; a failed or canceled
Claude turn resets it because Claude may have saved an incomplete turn.

The detector's configured credential and all `HECC_*` environment variables are
removed from the Claude child environment. The local key is never sent through
stdin or command-line arguments. Claude keeps its normal authentication and
project context. This is process-input separation, not filesystem isolation: a
permitted tool may still read files belonging to the same OS user.

The wrapper uses `dontAsk` permission mode. It does not approve new tool requests
or offer a permission dialog. Tool requests that are not already allowed are
denied and counted in the completion status. Native Claude slash commands, file
attachments, and resuming a wrapper session after exit are not implemented.

Ctrl-C cancels detection or terminates the active Claude process group. A process
that does not exit after termination is killed after two seconds. A Claude turn
has a ten-minute timeout; detection uses the provider's configured timeout. Ctrl-D
exits after canceling active work. No plaintext chat log is created by hecc;
Claude's own session persistence remains enabled for follow-up turns.

## Source map

| File | Responsibility |
| --- | --- |
| [`bin/hecc.ts`](../bin/hecc.ts) | CLI options, stdin, complete stdout results, sanitized errors |
| [`src/config.ts`](../src/config.ts) | Configuration validation, private storage, key initialization |
| [`src/env.ts`](../src/env.ts) | Provider overrides and credentials from `.env` |
| [`src/provider.ts`](../src/provider.ts) | Trusted-provider HTTP request and response checks |
| [`src/detection.ts`](../src/detection.ts) | Exact substring validation, occurrences, overlapping ranges |
| [`src/crypto.ts`](../src/crypto.ts) | AES-GCM markers and authenticated local decryption |
| [`src/chat.ts`](../src/chat.ts) | Protection before submission and conversation lifecycle |
| [`src/claude.ts`](../src/claude.ts) | Claude subprocess, protected stdin, streaming, cancellation |
| [`src/tui.ts`](../src/tui.ts) | Terminal editor, protected transcript display, keyboard controls |
| [`src/types.ts`](../src/types.ts) | Shared types and the runtime object guard |
| [`scripts/session-start.ts`](../scripts/session-start.ts) | Claude session reminder |
| [`test/`](../test/) | Synthetic tests and mock provider fixtures |

Run `npm run typecheck`, `npm test`, and `npm run validate:plugin` from the checkout.
The test suite uses local mock providers, so it does not need real credentials.
