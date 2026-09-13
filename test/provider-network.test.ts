import test from 'node:test';
import assert from 'node:assert/strict';
import { ProviderNetworkPolicy } from '../src/provider-network.js';

test('provider policy retains DNS addresses and recognizes canonical and mapped targets', async () => {
  let current = ['192.0.2.10', '2001:db8::10'];
  const policy = new ProviderNetworkPolicy(async () => current);
  await policy.refresh();
  current = ['192.0.2.11'];
  await policy.refresh();
  assert.deepEqual([...policy.addresses], ['192.0.2.10', '2001:db8::10', '192.0.2.11']);
  for (const host of ['api.anthropic.com', 'API.ANTHROPIC.COM.', '192.0.2.10', '192.0.2.11',
    '2001:db8::10', '[2001:db8::10]', '[::ffff:192.0.2.10]']) {
    assert.equal(await policy.blocks(host), true, host);
  }
  assert.equal(await policy.blocks('192.0.2.12'), false);
  assert.match(policy.hosts(), /192\.0\.2\.11 api\.anthropic\.com/);
});

test('invalid or missing provider DNS never yields an empty network policy', async () => {
  for (const addresses of [[], ['invalid'], ['192.0.2.1\nflush ruleset']]) {
    const policy = new ProviderNetworkPolicy(async () => addresses);
    await assert.rejects(policy.refresh(), /valid model provider addresses/);
    assert.equal(policy.addresses.size, 0);
  }
  const policy = new ProviderNetworkPolicy(async () => { throw new Error('DNS failed'); });
  await assert.rejects(policy.refresh(), /DNS failed/);
});
