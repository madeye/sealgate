# Step-by-step tool verification

Use this guide to reproduce SEALGATE's protection, decryption, gateway, and
plugin checks and compare the actual text at each boundary.

The [complete captured transcript](verification-output.txt) contains untruncated
stdin, stdout, stderr, exit codes, detector request/response bodies, and gateway
request/response bodies. It was recorded on 2026-09-13 with SEALGATE 0.4.0,
Node v24.20.0, Linux ARM64, against runtime source commit
`3f63714457c90870399b89999d6421dbb4004e78`.
The excerpts below come from that same run.

These checks execute the real compiled CLI, encryption, HTTP detector client,
and gateway against local mock services. The detector selects two predefined
synthetic strings; the mock upstream replies `Synthetic reply`. This verifies
integration and failure behavior. Live detection accuracy, native Claude tool
execution, and OS sandbox enforcement require the additional checks at the end.

## Before you start: build and capture a fresh run

Use a source checkout on Linux or macOS with Node.js 22 or later. From its root:

```sh
npm ci
npm run build
node scripts/verify-tools.mjs > /tmp/sealgate-verification.txt
verification_status=$?
cat /tmp/sealgate-verification.txt
printf 'Verification exit code: %s\n' "$verification_status"
test "$verification_status" -eq 0
```

The [verification runner](../scripts/verify-tools.mjs) performs steps 1–8 below
in order and asserts each pass condition. No global installation, provider key,
Claude login, or Docker daemon is needed. It uses an empty temporary working
directory, an isolated `SEALGATE_CONFIG_DIR`, and an allowlist of child environment
variables, so it does not load your checkout's `.env` or existing key. It starts
loopback HTTP servers on available ports and removes its temporary storage on exit.
The temporary directory must be outside Git repositories, as required by `init`.

A successful run exits 0 and ends with:

```text
PASS: all 8 verification steps completed.
```

The `command argv` arrays show the exact subprocess commands, relative to the
checkout; the runner supplies the shown stdin. String dumps use JSON quoting:
`""` means zero bytes, `\n` means LF, and `\r\n` means CRLF. There is no added
newline in CLI result text unless the input had one. Ciphertext, temporary ports,
request boundary IDs, and timestamps will differ on a new run. Compare assertions
and restored content rather than expecting identical ciphertext. The capture's
random encryption key was deleted, so reproduce a run to obtain its own round trip.

## 1. Initialize private configuration and key storage

The runner invokes `init` with its local detector URL and `--no-api-key`, then
checks directory/file permissions and key length without dumping the key.

```text
command argv: ["node","dist/bin/sealgate.js","init","--base-url","http://127.0.0.1:33429/v1","--model","synthetic-detector","--no-api-key"]
stdin: ""
stdout: ""
stderr: "sealgate: Initialized private config.json and key. Back up the key securely before use.\n"
exit code: 0
. permissions: "700"
config.json permissions: "600"
key permissions: "600"
key byte length: 32
PASS: private storage and 32-byte key created
```

Pass when the command exits 0, stdout is empty, the directory is mode `700`,
both files are mode `600`, and the key has 32 bytes. The initialization message
belongs to stderr even on success.

## 2. Protect repeated, Unicode, and multiline input

The runner pipes a synthetic email address twice and a multiline sensitive span
into `protect`. The mock detector returns this JSON inside the standard chat
completion envelope:

```json
{"sensitive_substrings":["alice@example.test","秘密\n123-45-6789"]}
```

The full detector HTTP request and envelope are in the transcript. Its user
message must exactly equal the CLI's original input, including line endings.

```text
command argv: ["node","dist/bin/sealgate.js","protect"]
stdin: "Draft a reply to alice@example.test.\r\n秘密\n123-45-6789\nAgain alice@example.test."
stdout: "Draft a reply to [[SEALGATE:v1:oyjjvI3XY9bdUuoKvhcLjGmCjtOaSJqEknLnb-0jgu4LoDH3TdSHDFSdO2WBRA]].\r\n[[SEALGATE:v1:eRSXzPG9lKgrvOXUp3wecDpvJCcnJM70HMOsmBnkLjYyKGjcvGwRonr1co3bTA]]\nAgain [[SEALGATE:v1:BNSLAxVzCLuO987hW2V_8anxRtD3tK2qwmPv7SlBDq3LzCn-bY9fTxf9RTwEFA]]."
stderr: ""
exit code: 0
PASS: three distinct ciphertext markers; detector received exact original input
```

Pass when neither detected string remains in stdout, three valid markers appear,
and all three markers differ. Manual `protect` encrypts each occurrence with a
fresh nonce. Surrounding text and line endings stay intact.

## 3. Verify the no-match case

When the detector returns an empty list, public text must pass through exactly.
This fixture has no trailing newline.

```text
command argv: ["node","dist/bin/sealgate.js","protect"]
stdin: "Public release notes."
stdout: "Public release notes."
stderr: ""
exit code: 0
detector response: "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"sensitive_substrings\\\":[]}\"}}]}"
PASS: no-match stdout is byte-for-byte unchanged
```

Pass when stdout equals stdin byte for byte, stderr is empty, and the exit code is 0.

## 4. Verify protection failures produce no prompt

First, the mock detector returns a substring that is absent from the input.
Then the runner submits step 2's ciphertext to `protect` again.

```text
command argv: ["node","dist/bin/sealgate.js","protect"]
stdin: "alice@example.test"
stdout: ""
stderr: "sealgate: Detection substring did not match the input; no protected prompt was produced.\n"
exit code: 1
detector response: "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"sensitive_substrings\\\":[\\\"not present in the input\\\"]}\"}}]}"
command argv: ["node","dist/bin/sealgate.js","protect"]
stdin: "Draft a reply to [[SEALGATE:v1:oyjjvI3XY9bdUuoKvhcLjGmCjtOaSJqEknLnb-0jgu4LoDH3TdSHDFSdO2WBRA]].\r\n[[SEALGATE:v1:eRSXzPG9lKgrvOXUp3wecDpvJCcnJM70HMOsmBnkLjYyKGjcvGwRonr1co3bTA]]\nAgain [[SEALGATE:v1:BNSLAxVzCLuO987hW2V_8anxRtD3tK2qwmPv7SlBDq3LzCn-bY9fTxf9RTwEFA]]."
stdout: ""
stderr: "sealgate: Input contains a reserved SEALGATE marker; protect original plaintext only.\n"
exit code: 1
PASS: both failures emit empty stdout; reserved-marker rejection makes no detector call
```

Pass when both commands exit 1 and produce zero stdout bytes. The diagnostic
must not echo the synthetic secret. The reserved-marker case must make no new
detector request. Never send the original input as a fallback after failure.

## 5. Inspect the gateway input and the upstream output

The runner starts the production gateway with a synthetic subscription token,
the same mock detector, and a capturing mock upstream. It sends `POST /v1/messages`
with these headers and body (decoded from the transcript for readability):

```json
{
  "authorization": "Bearer synthetic-subscription-token",
  "anthropic-version": "2023-06-01",
  "anthropic-beta": "oauth-2025-04-20",
  "content-type": "application/json"
}
```

```json
{
  "model": "claude-test",
  "max_tokens": 128,
  "system": "Contact alice@example.test",
  "messages": [
    {
      "role": "user",
      "content": "Draft for alice@example.test"
    },
    {
      "role": "assistant",
      "content": [
        {
          "type": "tool_use",
          "id": "toolu_1",
          "name": "Read",
          "input": {
            "path": "/data/alice@example.test"
          }
        }
      ]
    },
    {
      "role": "user",
      "content": [
        {
          "type": "tool_result",
          "tool_use_id": "toolu_1",
          "content": "File says alice@example.test\n秘密\n123-45-6789"
        }
      ]
    }
  ]
}
```

The mock upstream actually receives this protected JSON body:

```json
{
  "model": "claude-test",
  "max_tokens": 128,
  "system": "Contact [[SEALGATE:v1:s6Db68vj4bs_DXhl2VSeGT7vyYJ7hZNX6a2PN3dA7vcsWXQieWJxjDoWXuczXA]]",
  "messages": [
    {
      "role": "user",
      "content": "Draft for [[SEALGATE:v1:s6Db68vj4bs_DXhl2VSeGT7vyYJ7hZNX6a2PN3dA7vcsWXQieWJxjDoWXuczXA]]"
    },
    {
      "role": "assistant",
      "content": [
        {
          "type": "tool_use",
          "id": "toolu_1",
          "name": "Read",
          "input": {
            "path": "/data/[[SEALGATE:v1:s6Db68vj4bs_DXhl2VSeGT7vyYJ7hZNX6a2PN3dA7vcsWXQieWJxjDoWXuczXA]]"
          }
        }
      ]
    },
    {
      "role": "user",
      "content": [
        {
          "type": "tool_result",
          "tool_use_id": "toolu_1",
          "content": "File says [[SEALGATE:v1:s6Db68vj4bs_DXhl2VSeGT7vyYJ7hZNX6a2PN3dA7vcsWXQieWJxjDoWXuczXA]]\n[[SEALGATE:v1:KnKM26-IzTb0MEExcVqlBDmfSTf2UHrZcj7WHV1FDwPrtcM4jbdkrBbA-rvOGA]]"
        }
      ]
    }
  ]
}
```

The gateway returns:

```text
gateway response status: 200
gateway response body: "{\"content\":[{\"type\":\"text\",\"text\":\"Synthetic reply\"}]}"
```

Pass when the upstream receives one request, none of the fixture secrets remain
in its body, and recursively decrypting its string values restores the original
request exactly. The synthetic OAuth Authorization header must reach the upstream
and must not appear in the detector body. The response must pass through unchanged.
The full detector exchange and captured upstream headers are in the transcript.

The gateway reuses ciphertext for an identical span within its session, so the
email marker repeats here. This differs from manual `protect` in step 2.
The `Read` input and result above are HTTP fixtures; this step does not launch
Claude or execute a file-reading tool.

## 6. Verify blocked gateway requests never reach upstream

The runner adds `unsupported_field: "public text"` to step 5's request, then
retries the original schema while the detector returns a nonmatching substring.
The transcript contains both complete request bodies. Captured results:

```text
gateway response status: 400
gateway response body: "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"Gateway rejected an unsupported request schema.\"}}"
additional upstream requests: 0
gateway response status: 400
gateway response body: "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"Detection substring did not match the input; no protected prompt was produced.\"}}"
additional upstream requests: 0
PASS: both requests blocked with zero additional upstream calls
```

Pass when both responses are HTTP 400 and the upstream request count stays at
one from step 5: zero additional requests after either failure.

## 7. Decrypt offline and detect ciphertext tampering

The runner stops both mock HTTP servers and the gateway and removes its temporary
`config.json`. It decrypts step 2's output using only the remaining key, then
changes one base64url character in the first marker and retries.

```text
All mock servers stopped and config.json removed; only the local key remains.
command argv: ["node","dist/bin/sealgate.js","decrypt"]
stdin: "Draft a reply to [[SEALGATE:v1:oyjjvI3XY9bdUuoKvhcLjGmCjtOaSJqEknLnb-0jgu4LoDH3TdSHDFSdO2WBRA]].\r\n[[SEALGATE:v1:eRSXzPG9lKgrvOXUp3wecDpvJCcnJM70HMOsmBnkLjYyKGjcvGwRonr1co3bTA]]\nAgain [[SEALGATE:v1:BNSLAxVzCLuO987hW2V_8anxRtD3tK2qwmPv7SlBDq3LzCn-bY9fTxf9RTwEFA]]."
stdout: "Draft a reply to alice@example.test.\r\n秘密\n123-45-6789\nAgain alice@example.test."
stderr: ""
exit code: 0
command argv: ["node","dist/bin/sealgate.js","decrypt"]
stdin: "Draft a reply to [[SEALGATE:v1:AyjjvI3XY9bdUuoKvhcLjGmCjtOaSJqEknLnb-0jgu4LoDH3TdSHDFSdO2WBRA]].\r\n[[SEALGATE:v1:eRSXzPG9lKgrvOXUp3wecDpvJCcnJM70HMOsmBnkLjYyKGjcvGwRonr1co3bTA]]\nAgain [[SEALGATE:v1:BNSLAxVzCLuO987hW2V_8anxRtD3tK2qwmPv7SlBDq3LzCn-bY9fTxf9RTwEFA]]."
stdout: ""
stderr: "sealgate: Decryption failed: incorrect key or damaged ciphertext; no plaintext was produced.\n"
exit code: 1
PASS: offline round trip preserves exact bytes; tampering emits no plaintext
```

Pass when the first result exactly matches step 2's stdin, including Unicode,
CRLF, LF, and the absence of a trailing newline. The tampered input must exit 1
with empty stdout, so no partial plaintext escapes.

## 8. Verify the companion plugin hook

The runner executes `node dist/scripts/session-start.js` with empty stdin after
the provider configuration has been removed. The complete JSON stdout is in the
transcript. These fields are extracted from that captured stdout:

```json
{
  "hookEventName": "SessionStart",
  "systemMessage": "SEALGATE: For complete model-request inspection, launch sealgate claude from a separate local terminal (on Linux, after sealgate sandbox-build). Its gateway protects detected text in prompts, context, history, and tool results; Linux tools have direct, uninspected network access, while macOS blocks other network traffic by default. This plugin alone cannot intercept or modify requests. The narrower sealgate chat wrapper protects typed prompts only. For manual preprocessing, run sealgate protect, finish input with EOF (Ctrl-D), and paste only successful stdout. The trusted detection provider receives original text and detection can miss secrets."
}
```

```text
stderr: ""
exit code: 0
PASS: hook returns the expected reminder without provider configuration
```

Pass when stdout parses as JSON, `hookSpecificOutput.hookEventName` is
`SessionStart`, and `additionalContext` includes `Do not read SEALGATE keys`.
The hook supplies a reminder; it does not intercept requests or expose decryption.

## 9. Run the broader regression suite

From the checkout:

```sh
npm run typecheck
npm test
npm run validate:plugin
```

Plugin validation requires the Claude Code CLI. All three commands exited 0 in
this recorded run. The actual `npm test` summary was:

```text
ℹ tests 57
ℹ suites 0
ℹ pass 52
ℹ fail 0
ℹ cancelled 0
ℹ skipped 5
ℹ todo 0
ℹ duration_ms 1534.552932
```

Plugin validation ended with:

```text
✔ Validation passed
```

The default suite includes mock Claude chat checks for protected stdin, streamed
responses, session continuity, cancellation, and credential isolation. It also
checks gateway streaming, replay, proxies, and additional failure cases. A passing
suite must have zero failures; test counts can change as the project develops.
The five skips above are the opt-in Docker and macOS Seatbelt integration tests.

## 10. Verify native Claude and your live detector separately

These additional commands were **not run for the captured transcript**. Use them
to verify native tool execution and OS isolation on the machine you will use.
Install the native Claude binary first; the suites use synthetic subscription
credentials and a mock model upstream. CI currently pins Claude Code 2.1.270.

On Linux with a local Docker daemon:

```sh
node dist/bin/sealgate.js sandbox-build
npm run test:sandbox
```

On macOS:

```sh
npm run test:seatbelt
```

Pass when the applicable platform's integration tests execute and succeed, rather
than being skipped. They exercise workspace edits, hidden configuration, network
policy, and native Claude requests containing file and tool results. Linux tools
have direct uninspected network access except for the original provider's blocked
addresses; macOS blocks other networking by default. See the
[gateway guide](gateway.md) for the exact boundaries.

To additionally use your configured trusted detector, initialize SEALGATE and
configure the provider as described in the [README](../README.md#configure-a-trusted-provider),
then run the matching command from the directory containing your provider `.env`:

```sh
SEALGATE_TEST_LIVE=1 npm run test:sandbox   # Linux, after sandbox-build
SEALGATE_TEST_LIVE=1 npm run test:seatbelt  # macOS
```

This sends synthetic fixture context to your configured detector while retaining
a mock Anthropic upstream. It checks that the detector finds those fixture secrets;
it does not establish detection completeness for arbitrary inputs or confirm a
live Anthropic subscription. An actual `sealgate claude` session additionally
requires your current subscription login. Keep any live captures private if they
include real context or credentials.
