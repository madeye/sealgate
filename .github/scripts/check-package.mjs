import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [archive] = JSON.parse(await readFile(process.argv[2], 'utf8'));
const files = new Set(archive.files.map(file => file.path));
for (const file of [
  'package.json', 'README.md', 'LICENSE', 'dist/bin/sealgate.js',
  'dist/src/sandbox.js', 'dist/src/provider-network.js',
  'dist/scripts/relay.js', 'dist/scripts/firewall.js', 'dist/scripts/session-start.js',
  '.claude-plugin/plugin.json', 'hooks/hooks.json',
  'sandbox/Dockerfile', 'sandbox/seccomp.json', 'sandbox/profile.sb', 'sandbox/LICENSE.moby',
]) assert.ok(files.has(file), `Package is missing ${file}`);
for (const file of files) {
  assert.ok(!/(^|\/)\.env(?:\.|$)|(^|\/)(?:node_modules|test|\.git|\.github)(\/|$)/.test(file), `Unexpected private/development file: ${file}`);
  assert.ok(!/^(?:src|bin|scripts)\//.test(file), `Uncompiled source in package: ${file}`);
}
console.log(`Verified ${archive.filename}: ${files.size} distributable files.`);
