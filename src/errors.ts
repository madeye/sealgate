// Only these locally authored messages may reach stderr. Never forward errors
// from fetch, JSON parsing, crypto, the filesystem, or user-provided values.
export class HeccError extends Error {}

export function fail(message: string): never {
  throw new HeccError(message);
}

export function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}
