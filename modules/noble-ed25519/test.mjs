import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-ed25519.js', import.meta.url), 'utf8');
const idSource = fs.readFileSync(new URL('./ids.js', import.meta.url), 'utf8');
const ids = Object.fromEntries(
  [...idSource.matchAll(/export const Is(\w+) = function\(id\) \{ return id == BigInt\("(\d+)"\); \}/g)]
    .map((match) => [match[1], match[2]])
);

function run(operation, input) {
  const context = {
    FuzzerInput: JSON.stringify({ ...input, operation: ids[operation] }),
    FuzzerOutput: undefined,
  };
  vm.runInNewContext(bundle, context);
  return context.FuzzerOutput === undefined ? undefined : JSON.parse(context.FuzzerOutput);
}

const publicKey = run('ECC_PrivateToPublic', { priv: '1' });
assert.ok(publicKey);

const signature = run('ECDSA_Sign', { cleartext: '010203', priv: '1' });
assert.ok(signature);
assert.equal(run('ECDSA_Verify', {
  cleartext: '010203',
  pub_x: signature.pub[0],
  pub_y: '0',
  sig_r: signature.signature[0],
  sig_s: signature.signature[1],
}), true);

assert.equal(run('ECDSA_Verify', {
  cleartext: '010204',
  pub_x: signature.pub[0],
  pub_y: '0',
  sig_r: signature.signature[0],
  sig_s: signature.signature[1],
}), false);

console.log('noble-ed25519 adapter tests passed');
