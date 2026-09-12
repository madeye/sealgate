import { fail } from './errors.js';
import { isRecord } from './types.js';
import type { DetectionRange } from './types.js';

export const DEFAULT_INSTRUCTIONS = `Detect sensitive text in the user's prompt. Cover credentials (passwords, API keys, access tokens, private keys), personal identifiers (government IDs and other identifying numbers), contact details (email addresses, phone numbers, postal addresses), financial information (bank accounts, payment card numbers, private financial figures), and explicitly marked confidential content (including the entire content between confidential tags or delimiters).`;

export const MAX_MATCHES = 100_000;

export function detectionRanges(prompt: string, result: unknown): DetectionRange[] {
  if (!isRecord(result) ||
      Object.keys(result).length !== 1 || !Array.isArray(result.sensitive_substrings) ||
      result.sensitive_substrings.length > 10_000) {
    fail('Invalid detection result; no protected prompt was produced.');
  }
  const ranges: DetectionRange[] = [];
  for (const value of new Set(result.sensitive_substrings)) {
    if (typeof value !== 'string' || !value.length || !value.isWellFormed()) {
      fail('Invalid detection substring; no protected prompt was produced.');
    }
    let start = prompt.indexOf(value);
    if (start < 0) fail('Detection substring did not match the input; no protected prompt was produced.');
    while (start >= 0) {
      ranges.push({ start, end: start + value.length });
      if (ranges.length > MAX_MATCHES) fail('Too many detection matches; no protected prompt was produced.');
      // Advance by one code unit to include overlapping occurrences (aba in ababa).
      start = prompt.indexOf(value, start + 1);
    }
  }
  ranges.sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: DetectionRange[] = [];
  for (const range of ranges) {
    const previous = merged.at(-1);
    if (previous && range.start < previous.end) previous.end = Math.max(previous.end, range.end);
    else merged.push({ ...range });
  }
  return merged;
}
