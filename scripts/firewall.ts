// A short-lived NET_ADMIN helper shares only the relay network namespace.
// It never mounts the workspace, gateway sockets, or credentials.
import { execFileSync } from 'node:child_process';
import { isIP } from 'node:net';

const addresses = process.argv.slice(2);
if (!addresses.length || addresses.some(address => !isIP(address))) process.exit(1);
// nft applies this complete replacement atomically; no unfiltered refresh window.
const rules = [
  'add table inet sealgate',
  'flush table inet sealgate',
  'add chain inet sealgate output { type filter hook output priority -10; policy accept; }',
  ...addresses.map(address => `add rule inet sealgate output ${isIP(address) === 6 ? 'ip6' : 'ip'} daddr ${address} reject`),
].join('\n') + '\n';
try { execFileSync('nft', ['-f', '-'], { input: rules, timeout: 10_000, stdio: ['pipe', 'ignore', 'ignore'] }); }
catch { process.stderr.write('Cannot install the model provider network block.\n'); process.exit(1); }
