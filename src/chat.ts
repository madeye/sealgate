import { randomUUID } from 'node:crypto';
import { protectText, validatePrompt } from './crypto.js';
import { detectSensitive } from './provider.js';
import { runClaude } from './claude.js';
import type { ClaudeOptions, ClaudeResult } from './claude.js';
import { fail } from './errors.js';
import type { Environment, ProviderSettings } from './types.js';

export interface ChatCallbacks {
  onProtected: (prompt: string) => void;
  onText: (text: string) => void;
  onActivity: (text: string) => void;
}

export function claudeEnvironment(env: Environment, credentialName: string | null): Environment {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !name.startsWith('HECC_') && name !== credentialName));
}

export class ProtectedChat {
  private sessionId = randomUUID();
  private resume = false;
  private busy = false;

  constructor(
    private readonly settings: ProviderSettings,
    private readonly key: Buffer,
    private readonly claudeOptions: ClaudeOptions = {},
  ) {}

  reset(): void {
    if (this.busy) fail('Cancel the active turn before starting a new conversation.');
    this.sessionId = randomUUID();
    this.resume = false;
  }

  async send(prompt: string, callbacks: ChatCallbacks, signal?: AbortSignal): Promise<ClaudeResult> {
    if (this.busy) fail('A chat turn is already running.');
    if (!prompt.trim()) fail('Enter a prompt first.');
    if (Buffer.byteLength(prompt) > 1024 * 1024) fail('Input exceeds the size limit; no prompt was sent to Claude.');
    validatePrompt(prompt);
    this.busy = true;
    let dispatched = false;
    try {
      callbacks.onActivity('Detecting sensitive text…');
      const detection = await detectSensitive(prompt, this.settings.config, this.settings.env, signal);
      const protectedPrompt = protectText(prompt, detection, this.key);
      if (signal?.aborted) fail('Protection canceled; no prompt was sent to Claude.');
      callbacks.onProtected(protectedPrompt);
      callbacks.onActivity('Waiting for Claude…');
      dispatched = true;
      const result = await runClaude(protectedPrompt, {
        sessionId: this.sessionId, resume: this.resume, signal,
        onText: callbacks.onText, onActivity: callbacks.onActivity,
      }, {
        ...this.claudeOptions,
        env: claudeEnvironment(this.claudeOptions.env ?? process.env, this.settings.config.apiKeyEnv),
      });
      this.resume = true;
      return result;
    } catch (error) {
      // An incomplete Claude turn may have been persisted. Never silently resume
      // an ambiguous history; detection failures leave the existing session alone.
      if (dispatched) { this.sessionId = randomUUID(); this.resume = false; }
      throw error;
    } finally { this.busy = false; }
  }
}
