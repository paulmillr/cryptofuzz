import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-secp256k1.js', import.meta.url), 'utf8');
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
assert.deepEqual(publicKey, [
  '55066263022277343669578718895168534326250603453777594175500187360389116729240',
  '32670510020758816978083085130507043184471273380659243275938904335757337482424',
]);

const signature = run('ECDSA_Sign', { cleartext: '01'.padStart(64, '0'), priv: '1' });
assert.ok(signature);
assert.equal(run('ECDSA_Verify', {
  cleartext: '01'.padStart(64, '0'),
  pub_x: signature.pub[0],
  pub_y: signature.pub[1],
  sig_r: signature.signature[0],
  sig_s: signature.signature[1],
}), true);

assert.deepEqual(run('ECC_Point_Dbl', {
  a_x: publicKey[0],
  a_y: publicKey[1],
}), run('ECC_PrivateToPublic', { priv: '2' }));

console.log('noble-secp256k1 adapter tests passed');
