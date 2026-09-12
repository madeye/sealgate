export type Environment = Readonly<Record<string, string | undefined>>;

export interface Config {
  version: 1;
  baseUrl: string;
  model: string;
  apiKeyEnv: string | null;
  timeoutMs: number;
  detectionInstructions: string;
  additionalCategories: string[];
}

export interface InitOptions {
  baseUrl: string;
  model: string;
  apiKeyEnv?: string | null;
  timeoutMs?: number;
}

export interface DetectionRange {
  start: number;
  end: number;
}

export interface ProviderSettings {
  config: Config;
  env: Environment;
}

// JSON from disk or a provider remains unknown until checked at runtime.
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
