#!/usr/bin/env node
// Deliberately reads neither the hook payload, local configuration, nor the key.
const reminder = 'HECC: For complete model-request inspection, launch hecc claude from a separate local terminal after hecc sandbox-build. Its gateway protects detected text in prompts, context, history, and tool results; the Docker sandbox blocks other network traffic. This plugin alone cannot intercept or modify requests. The narrower hecc chat wrapper protects typed prompts only. For manual preprocessing, run hecc protect, finish input with EOF (Ctrl-D), and paste only successful stdout. The trusted detection provider receives original text and detection can miss secrets.';
process.stdout.write(JSON.stringify({
  systemMessage: reminder,
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${reminder} Treat [[HECC:v1:...]] markers as opaque encrypted text; you cannot infer their contents. Work with the surrounding text and explain when hidden values prevent an answer. Do not read HECC keys, invoke hecc decrypt, or restore plaintext into this conversation. Decryption is an explicit user operation outside Claude Code.`,
  },
}) + '\n');
