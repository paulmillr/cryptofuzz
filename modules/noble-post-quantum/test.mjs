import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-post-quantum.js', import.meta.url), 'utf8');
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

const kemKeys = run('KEM_KeyGen', {
  kemType: ids.ML_KEM_768,
  seed: '00'.repeat(64),
});
assert.equal(kemKeys.publicKey.length, 1184 * 2);
assert.equal(kemKeys.secretKey.length, 2400 * 2);

const encapsulated = run('KEM_Encapsulate', {
  kemType: ids.ML_KEM_768,
  publicKey: kemKeys.publicKey,
  coins: '01'.repeat(32),
});
assert.equal(encapsulated.ciphertext.length, 1088 * 2);
assert.equal(encapsulated.sharedSecret.length, 32 * 2);
assert.equal(run('KEM_Decapsulate', {
  kemType: ids.ML_KEM_768,
  secretKey: kemKeys.secretKey,
  ciphertext: encapsulated.ciphertext,
}), encapsulated.sharedSecret);

const sigKeys = run('PQSIG_KeyGen', {
  pqSignatureType: ids.ML_DSA_44,
  seed: '02'.repeat(32),
});
const signature = run('PQSIG_Sign', {
  pqSignatureType: ids.ML_DSA_44,
  secretKey: sigKeys.secretKey,
  message: '616263',
  context: '637478',
  extraEntropy: '',
});
assert.equal(run('PQSIG_Verify', {
  pqSignatureType: ids.ML_DSA_44,
  publicKey: sigKeys.publicKey,
  message: '616263',
  signature,
  context: '637478',
}), true);
assert.equal(run('PQSIG_Verify', {
  pqSignatureType: ids.ML_DSA_44,
  publicKey: sigKeys.publicKey,
  message: '616264',
  signature,
  context: '637478',
}), false);

assert.equal(run('KEM_KeyGen', {
  kemType: ids.ML_KEM_768,
  seed: '00'.repeat(63),
}), undefined);

console.log('noble-post-quantum adapter tests passed');
