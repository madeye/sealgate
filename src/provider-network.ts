import { Resolver } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { fail, hasErrorCode } from './errors.js';

export const MODEL_PROVIDER_HOST = 'api.anthropic.com';
export const MODEL_PROVIDER_UPSTREAM = `https://${MODEL_PROVIDER_HOST}`;

async function providerAddresses(): Promise<string[]> {
  const resolver = new Resolver({ timeout: 3000, tries: 2 });
  const answers = await Promise.allSettled([
    resolver.resolve4(MODEL_PROVIDER_HOST), resolver.resolve6(MODEL_PROVIDER_HOST),
  ]);
  const addresses: string[] = [];
  for (const answer of answers) {
    if (answer.status === 'fulfilled') addresses.push(...answer.value);
    else if (!hasErrorCode(answer.reason, 'ENODATA')) fail('Cannot resolve the model provider for the Linux network block.');
  }
  return addresses;
}

/** Retain every observed provider address for the session, including old DNS answers. */
export class ProviderNetworkPolicy {
  readonly addresses = new Set<string>();
  // Resolver injection is for deterministic tests, never CLI configuration.
  constructor(private readonly resolve: () => Promise<string[]> = providerAddresses) {}

  async refresh(): Promise<void> {
    const addresses = await this.resolve();
    if (!addresses.length || addresses.some(address => !isIP(address))) {
      fail('Cannot resolve valid model provider addresses for the Linux network block.');
    }
    addresses.forEach(address => this.addresses.add(address));
  }

  hosts(): string {
    return '127.0.0.1 localhost\n::1 localhost\n' +
      [...this.addresses].map(address => `${address} ${MODEL_PROVIDER_HOST}\n`).join('');
  }

  /** Checks CONNECT authorities, including IPv4-mapped IPv6 and DNS aliases. */
  async blocks(hostname: string): Promise<boolean> {
    const host = hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    if (host === MODEL_PROVIDER_HOST) return true;
    const block = new BlockList();
    for (const address of this.addresses) block.addAddress(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');
    const isBlocked = (address: string): boolean => block.check(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');
    if (isIP(host)) return isBlocked(host);
    const resolver = new Resolver({ timeout: 3000, tries: 2 });
    const answers = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
    let resolved = false;
    for (const answer of answers) {
      if (answer.status === 'fulfilled') {
        resolved ||= answer.value.length > 0;
        if (answer.value.some(isBlocked)) return true;
      } else if (!hasErrorCode(answer.reason, 'ENODATA')) return true;
    }
    return !resolved;
  }
}
