# Security model

`hecc claude` protects detected spans in complete outbound model requests and
blocks other network traffic. The older `hecc protect` and `hecc chat` commands
cover submitted prompts only. Its encryption
and detection steps have different guarantees. This page describes what each
participant receives and the limits to consider when using the output.

## Who sees what

| Participant | Original prompt | Provider API credential | Local encryption key | Protected output |
| --- | --- | --- | --- | --- |
| Your local CLI | Yes | During protection | Yes | Yes |
| Trusted detection endpoint | Yes | When authentication is enabled | No | Not sent by hecc |
| Claude Code | Only if you send it separately | Not sent by hecc | Not sent by hecc | Sent by hecc chat, or pasted by you |

The table describes the prompt-only workflows. In `hecc claude`, **local Claude
sees original text**; the gateway protects it before it reaches remote Anthropic.
The Docker launcher hides the host key directory, provider environment and root
`.env`, and permits network access only through the inspecting gateway. Anthropic
receives its own subscription OAuth credential as required for authentication;
that credential is not sent to the detector. See [gateway boundaries](gateway.md).

Choose a detection provider that you trust with the entire original prompt. A
local vLLM service can keep detection on your machine, but its own logs and access
controls still matter. `hecc` does not change the provider's retention policy or
logging configuration.

## Detection is not a guarantee

A model may miss sensitive text, misinterpret a category, or follow instructions
embedded in the prompt. Exact-match validation rejects invented or malformed
spans, but it cannot detect an omitted secret. In particular, a valid empty
detection list passes the full original prompt through unchanged.

Default categories and additional instructions help guide detection; they are not
an exhaustive secret scanner. Review the surrounding text before sending it. A
successful synthetic test demonstrates that example works, not that every future
secret will be detected.

## Cryptographic boundaries

AES-256-GCM hides matched content and authenticates each marker using the local
key. Fresh nonces make new encryptions independent. The gateway reuses ciphertext
for repeated spans within a session, revealing equality to preserve stable history. Without
the key, Claude cannot interpret the encrypted values or compute on them.

Markers reveal approximate plaintext lengths and where spans occur. Surrounding
text may reveal identities or confidential facts by itself. Individual marker
authentication does not cover the whole prompt: markers can be deleted or moved
without a document-level integrity failure. If the reserved marker prefix is
changed beyond recognition, the decoder treats it as ordinary text.

The v1 format has no key identifier or automatic key rotation. Losing the key
makes its ciphertext unrecoverable. Back up the binary key securely; anyone who
obtains it can decrypt the corresponding markers.

## Local storage and execution

The encryption key stays outside Git repositories in a directory owned by the
user with mode `700`, in a file with mode `600`. Provider credentials can reside
in a private `.env`, which this project ignores in Git and excludes from packages.
These permissions do not isolate processes running under the same OS account.

Outside the enforced `hecc claude` launcher, the Claude plugin's instruction to avoid reading keys or running decryption is
guidance, not an access-control boundary. A tool running as your user may still
read your files. Run decryption yourself in a separate terminal, and use OS-level
isolation if local agent access is a threat you need to prevent.

`hecc chat` passes only protected prompts to the Claude child through stdin and
removes detector credentials from its inherited environment. It does not sanitize
Claude's workspace files, hooks, MCP servers, or other context. Print mode uses
your normal Claude configuration, with new tool approvals denied by `dontAsk`.
Run it from a project you trust. The wrapper does not provide an OS sandbox.

The TUI's original prompt is visible in its local draft editor until protection
succeeds. Only the protected display is retained in its in-memory conversation.
The wrapper does not save a transcript, but Claude can save its own protected
session history, and terminal recording software may capture your draft.

Terminal input is echoed. Scrollback, copied text, redirected files, backups,
provider logs, and clipboard contents can retain plaintext. JavaScript strings
cannot be reliably zeroized. This version does not protect against a compromised
local machine.

## Failure behavior

Provider HTTP errors, timeouts, invalid detection output, unsafe storage, and
cryptographic failures exit unsuccessfully. The CLI buffers results before
printing, so these failures produce no partial prompt or partial decrypted text.
Diagnostics do not include prompts, provider response bodies, or credentials.

Do not treat a failed command as permission to forward the original input. Check
the exit code when scripting, and copy only a successful protected result.

## Scope

In `hecc protect` and `hecc chat`, direct Claude input, source files, tool results,
and other context remain outside protection. The `hecc claude` gateway instead
inspects all supported outgoing model-request text, including file/tool context
and history. Opaque uploads and unknown protocols are blocked. Other network
traffic cannot bypass the gateway because the native CLI and its descendants run
in a networkless Docker namespace with host Unix sockets denied by seccomp.

This protects remote egress, not local plaintext at rest. Native Claude can keep
original content in the temporary home until it is removed on exit. The project
is writable, so tool changes to files persist. Host programs that later execute
those files are outside confinement. The host kernel, Docker daemon, HECC process,
terminal and trusted detector remain trusted. Encoded secrets and adversarial
inputs can evade model detection; interception is not a guarantee of detection.
Read [the full gateway guide](gateway.md) for supported features and limits.

See the [usage guide](../README.md) for configuration, local decryption, backups,
and limits, and [how it works](how-it-works.md) for the marker construction.
