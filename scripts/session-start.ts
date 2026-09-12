#!/usr/bin/env node
// Deliberately reads neither the hook payload, local configuration, nor the key.
const reminder = 'HECC: Use hecc chat in a separate local terminal to protect prompts automatically before sending them to Claude Code. For manual preprocessing, run hecc protect, finish input with EOF (Ctrl-D), and paste only its successful stdout. The configured trusted detection provider receives the original prompt. Detection can miss secrets. Only text passed through the helper is protected; direct input, files, tool results, and history are outside its scope.';
process.stdout.write(JSON.stringify({
  systemMessage: reminder,
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${reminder} Treat [[HECC:v1:...]] markers as opaque encrypted text; you cannot infer their contents. Work with the surrounding text and explain when hidden values prevent an answer. Do not read HECC keys, invoke hecc decrypt, or restore plaintext into this conversation. Decryption is an explicit user operation outside Claude Code.`,
  },
}) + '\n');
