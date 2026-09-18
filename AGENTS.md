# Repository Guidelines

## Project Structure & Module Organization

SEALGATE is a TypeScript CLI that detects and encrypts sensitive text before Claude Code sends requests remotely. `bin/` contains the CLI entry point; `src/` implements detection, encryption, providers, the gateway, proxy, and platform sandboxes. `scripts/` holds runtime helpers and verification utilities. Tests live in `test/`, with synthetic fixtures in `test/fixtures/`. `sandbox/` contains Linux sandbox resources; `.claude-plugin/` and `hooks/` define the companion plugin. Documentation lives in `docs/`, and website assets in `site/`. Generated JavaScript goes into `dist/`; edit TypeScript sources instead.

## Build, Test, and Development Commands

Use Node.js 22 or later.

- `npm ci`: install locked dependencies and build through the prepare hook.
- `npm run build`: compile TypeScript into `dist/`.
- `npm run typecheck`: check types without emitting files.
- `npm test`: build and run the default Node test suite.
- `node dist/bin/sealgate.js --help`: run the built CLI locally.
- `npm run test:sandbox`: run Docker integration tests; first run `node dist/bin/sealgate.js sandbox-build` on Linux.
- `npm run test:seatbelt`: run macOS sandbox integration tests.
- `npm run validate:plugin`: validate plugin metadata using the installed Claude CLI.

Sandbox integration checks require native Claude and the corresponding platform backend.

## Coding Style & Naming Conventions

Follow existing strict TypeScript and ES-module conventions: two-space indentation, single-quoted strings, semicolons, and `.js` extensions in relative imports. Use camelCase for functions and variables, PascalCase for types and classes, and descriptive kebab-case module filenames. No standalone formatter or linter is configured; type checking is the static validation command.

## Testing Guidelines

Use `node:test` and `node:assert/strict`. Name files `test/<module>.test.ts` and describe observable behavior in test names. Add regression coverage for changed behavior, particularly malformed inputs, cancellation, authentication, and cleanup. Prefer synthetic fixtures and mock providers. No numeric coverage threshold is configured. Run the relevant platform checks when changing sandbox behavior.

## Commit & Pull Request Guidelines

Create a descriptive branch before edits, such as `fix/proxy-timeout` or `docs/repository-guidelines`; never commit directly to `main` or `master`. History uses concise imperative subjects, sometimes prefixed with `fix:` or `docs:`. Before every push, run `npm run typecheck` and `npm test`, plus applicable integration checks. PRs should explain the problem, behavior changes, related issues, and validation results; include screenshots for visible UI changes.

## Security & Configuration

Keep provider credentials in environment variables and encryption keys outside Git repositories. Preserve fail-closed behavior and consult `docs/security.md` before changing trust boundaries. Never include real secrets in tests, logs, or documentation.
