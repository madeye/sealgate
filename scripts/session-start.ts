#!/usr/bin/env node
// Deliberately reads neither the hook payload, local configuration, nor the key.
const reminder = 'SEALGATE: For complete model-request inspection, launch sealgate claude from a separate local terminal (on Linux, after sealgate sandbox-build). Its gateway protects detected text in prompts, context, history, and tool results; the OS sandbox blocks other network traffic. This plugin alone cannot intercept or modify requests. The narrower sealgate chat wrapper protects typed prompts only. For manual preprocessing, run sealgate protect, finish input with EOF (Ctrl-D), and paste only successful stdout. The trusted detection provider receives original text and detection can miss secrets.';
process.stdout.write(JSON.stringify({
  systemMessage: reminder,
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${reminder} Treat [[SEALGATE:v1:...]] markers as opaque encrypted text; you cannot infer their contents. Work with the surrounding text and explain when hidden values prevent an answer. Do not read SEALGATE keys, invoke sealgate decrypt, or restore plaintext into this conversation. Decryption is an explicit user operation outside Claude Code.`,
  },
}) + '\n');
