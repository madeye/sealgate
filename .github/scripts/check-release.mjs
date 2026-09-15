import assert from 'node:assert/strict';
import { appendFile, readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(process.argv[2], 'utf8'));
const source = JSON.parse(await readFile('package.json', 'utf8'));
assert.equal(manifest.name, '@m0d8ye/sealgate');
assert.equal(manifest.version, source.version, 'Artifact and checkout versions must match');
assert.equal(manifest.private, undefined, 'Package must be publishable');
assert.equal(process.env.RELEASE_TAG, `v${manifest.version}`, 'Release tag must be v followed by the package version');
const prerelease = manifest.version.includes('-');
assert.equal(process.env.RELEASE_PRERELEASE, String(prerelease), 'GitHub prerelease status must match the package version');
const tag = prerelease ? 'next' : 'latest';
await appendFile(process.env.GITHUB_OUTPUT, `dist-tag=${tag}\n`);
console.log(`Validated ${manifest.name}@${manifest.version} for npm tag ${tag}.`);
