import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-ciphers.js', import.meta.url), 'utf8');
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

function encrypt(cipherType, {
  cleartext = '',
  key,
  iv = '',
  aad,
  tagSize,
  ciphertextSize = cleartext.length / 2 + 64,
} = {}) {
  return run('SymmetricEncrypt', {
    cleartext,
    cipher: { cipherType: ids[cipherType], key, iv },
    aad_enabled: aad !== undefined,
    aad: aad ?? '',
    tagSize_enabled: tagSize !== undefined,
    tagSize: tagSize ?? 0,
    ciphertextSize,
    modifier: '',
  });
}

function decrypt(cipherType, encrypted, {
  key,
  iv = '',
  aad,
  cleartextSize,
} = {}) {
  return run('SymmetricDecrypt', {
    ciphertext: encrypted.ciphertext,
    cipher: { cipherType: ids[cipherType], key, iv },
    aad_enabled: aad !== undefined,
    aad: aad ?? '',
    tag_enabled: encrypted.tag !== undefined,
    tag: encrypted.tag ?? '',
    cleartextSize,
    modifier: '',
  });
}

function roundTrip(cipherType, {
  keyLength,
  ivLength = 0,
  aead = false,
  kind,
}) {
  const key = '01'.repeat(keyLength);
  const iv = '02'.repeat(ivLength);
  const aad = aead ? 'a0a1a2a3' : undefined;
  let cleartext = '00112233445566778899aabbccddeeff102030';
  if (kind === 'ecb') cleartext = cleartext.slice(0, 32);
  if (kind === 'aeskw') cleartext = cleartext.slice(0, 32);
  if (kind === 'aeskwp') cleartext = cleartext.slice(0, 14);

  const encrypted = encrypt(cipherType, {
    cleartext,
    key,
    iv,
    aad,
    tagSize: aead ? 16 : undefined,
  });
  assert.ok(encrypted, `${cipherType} encryption`);
  assert.equal(encrypted.tag?.length, aead ? 32 : undefined, `${cipherType} tag`);
  assert.equal(decrypt(cipherType, encrypted, {
    key,
    iv,
    aad,
    cleartextSize: cleartext.length / 2,
  }), cleartext, `${cipherType} round trip`);
}

const supported = [
  ['AES_128_ECB', 16, 0, false, 'ecb'],
  ['AES_192_ECB', 24, 0, false, 'ecb'],
  ['AES_256_ECB', 32, 0, false, 'ecb'],
  ['AES_128_CBC', 16, 16, false, 'cbc'],
  ['AES_192_CBC', 24, 16, false, 'cbc'],
  ['AES_256_CBC', 32, 16, false, 'cbc'],
  ['AES_128_CTR', 16, 16, false, 'ctr'],
  ['AES_192_CTR', 24, 16, false, 'ctr'],
  ['AES_256_CTR', 32, 16, false, 'ctr'],
  ['AES_128_CFB', 16, 16, false, 'cfb'],
  ['AES_192_CFB', 24, 16, false, 'cfb'],
  ['AES_256_CFB', 32, 16, false, 'cfb'],
  ['AES_128_CFB128', 16, 16, false, 'cfb'],
  ['AES_192_CFB128', 24, 16, false, 'cfb'],
  ['AES_256_CFB128', 32, 16, false, 'cfb'],
  ['AES_128_GCM', 16, 12, true, 'gcm'],
  ['AES_192_GCM', 24, 12, true, 'gcm'],
  ['AES_256_GCM', 32, 12, true, 'gcm'],
  ['AES_128_GCM_SIV', 16, 12, true, 'gcmsiv'],
  ['AES_256_GCM_SIV', 32, 12, true, 'gcmsiv'],
  ['AES_128_SIV_CMAC', 32, 12, true, 'aessiv'],
  ['AES_192_SIV_CMAC', 48, 12, true, 'aessiv'],
  ['AES_256_SIV_CMAC', 64, 12, true, 'aessiv'],
  ['AES_128_WRAP', 16, 0, false, 'aeskw'],
  ['AES_192_WRAP', 24, 0, false, 'aeskw'],
  ['AES_256_WRAP', 32, 0, false, 'aeskw'],
  ['AES_128_WRAP_PAD', 16, 0, false, 'aeskwp'],
  ['AES_192_WRAP_PAD', 24, 0, false, 'aeskwp'],
  ['AES_256_WRAP_PAD', 32, 0, false, 'aeskwp'],
  ['CHACHA20', 32, 12, false, 'chacha20'],
  ['CHACHA20_POLY1305', 32, 12, true, 'chacha20poly1305'],
  ['XCHACHA20_POLY1305', 32, 24, true, 'xchacha20poly1305'],
  ['SALSA20_128', 16, 8, false, 'salsa20'],
  ['SALSA20_256', 32, 8, false, 'salsa20'],
];

for (const [cipherType, keyLength, ivLength, aead, kind] of supported) {
  roundTrip(cipherType, { keyLength, ivLength, aead, kind });
}

const ecbVector = encrypt('AES_128_ECB', {
  key: '000102030405060708090a0b0c0d0e0f',
  cleartext: '00112233445566778899aabbccddeeff',
});
assert.deepEqual(ecbVector, { ciphertext: '69c4e0d86a7b0430d8cdb78070b4c55a' });

const cbcVector = encrypt('AES_128_CBC', {
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  iv: '000102030405060708090a0b0c0d0e0f',
  cleartext: '6bc1bee22e409f96e93d7e117393172a',
});
assert.equal(cbcVector.ciphertext.slice(0, 32), '7649abac8119b246cee98e9b12e9197d');
assert.equal(cbcVector.ciphertext.length, 64);

assert.deepEqual(encrypt('AES_128_CTR', {
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  iv: 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
  cleartext: '6bc1bee22e409f96e93d7e117393172a',
}), { ciphertext: '874d6191b620e3261bef6864990db6ce' });

const cfbVector = encrypt('AES_128_CFB', {
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  iv: '000102030405060708090a0b0c0d0e0f',
  cleartext: '6bc1bee22e409f96e93d7e117393172a',
});
assert.deepEqual(cfbVector, { ciphertext: '3b3fd92eb72dad20333449f8e83cfb4a' });
assert.deepEqual(encrypt('AES_128_CFB128', {
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  iv: '000102030405060708090a0b0c0d0e0f',
  cleartext: '6bc1bee22e409f96e93d7e117393172a',
}), cfbVector);

assert.deepEqual(encrypt('AES_128_GCM', {
  key: '00'.repeat(16),
  iv: '00'.repeat(12),
  cleartext: '',
  tagSize: 16,
}), { ciphertext: '', tag: '58e2fccefa7e3061367f1d57a4e7455a' });

const exactFitAead = encrypt('AES_128_GCM', {
  key: '00'.repeat(16),
  iv: '00'.repeat(12),
  cleartext: '0011223344',
  tagSize: 16,
  ciphertextSize: 5,
});
assert.ok(exactFitAead);
assert.equal(exactFitAead.ciphertext.length, 10);
assert.equal(exactFitAead.tag.length, 32);

assert.deepEqual(encrypt('AES_128_GCM_SIV', {
  key: '01000000000000000000000000000000',
  iv: '030000000000000000000000',
  cleartext: '',
  tagSize: 16,
}), { ciphertext: '', tag: 'dc20e2d83f25705bb49e439eca56de25' });

const sivVector = encrypt('AES_128_SIV_CMAC', {
  key: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
  iv: '',
  aad: '101112131415161718191a1b1c1d1e1f2021222324252627',
  cleartext: '112233445566778899aabbccddee',
  tagSize: 16,
});
assert.deepEqual(sivVector, {
  ciphertext: '40c02b9690c4dc04daef7f6afe5c',
  tag: '85632d07c6e8f37f950acd320a2ecc93',
});

assert.deepEqual(encrypt('AES_128_WRAP', {
  key: '000102030405060708090a0b0c0d0e0f',
  cleartext: '00112233445566778899aabbccddeeff',
}), { ciphertext: '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5' });

assert.deepEqual(encrypt('AES_192_WRAP_PAD', {
  key: '5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8',
  cleartext: 'c37b7e6492584340bed12207808941155068f738',
}), { ciphertext: '138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a' });

assert.deepEqual(encrypt('CHACHA20', {
  key: '00'.repeat(32),
  iv: '00'.repeat(12),
  cleartext: '00'.repeat(64),
  ciphertextSize: 64,
}), {
  ciphertext: '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7d' +
    'a41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
});

assert.deepEqual(encrypt('SALSA20_256', {
  key: '00'.repeat(32),
  iv: '00'.repeat(8),
  cleartext: '00'.repeat(64),
  ciphertextSize: 64,
}), {
  ciphertext: '9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee6' +
    '3de9c0da2bd7f91ebcb2639bf989c6251b29bf38d39a9bdce7c55f4b2ac12a39',
});

assert.equal(encrypt('AES_128_ECB', {
  key: '00'.repeat(16),
  cleartext: '00',
}), undefined);
assert.equal(encrypt('AES_128_CTR', {
  key: '00'.repeat(15),
  iv: '00'.repeat(16),
  cleartext: '00',
}), undefined);
assert.equal(encrypt('AES_128_CTR', {
  key: '00'.repeat(16),
  iv: '00'.repeat(16),
  cleartext: '00',
  aad: '',
}), undefined);
assert.equal(encrypt('AES_128_GCM', {
  key: '00'.repeat(16),
  iv: '00'.repeat(12),
  cleartext: '',
}), undefined);
assert.equal(encrypt('AES_128_GCM', {
  key: '00'.repeat(16),
  iv: '00'.repeat(7),
  cleartext: '',
  tagSize: 16,
}), undefined);
assert.equal(encrypt('AES_128_GCM', {
  key: '00'.repeat(16),
  iv: '00'.repeat(12),
  cleartext: '',
  tagSize: 12,
}), undefined);
assert.equal(encrypt('AES_128_WRAP', {
  key: '00'.repeat(16),
  iv: '00'.repeat(8),
  cleartext: '00'.repeat(16),
}), undefined);
assert.equal(encrypt('AES_128_CBC', {
  key: '00'.repeat(16),
  iv: '00'.repeat(16),
  cleartext: '',
  ciphertextSize: 15,
}), undefined);

const authenticated = encrypt('CHACHA20_POLY1305', {
  key: '10'.repeat(32),
  iv: '20'.repeat(12),
  aad: 'aabbccdd',
  cleartext: '0011223344',
  tagSize: 16,
});
assert.equal(decrypt('CHACHA20_POLY1305', {
  ...authenticated,
  tag: (authenticated.tag[0] === '0' ? '1' : '0') + authenticated.tag.slice(1),
}, {
  key: '10'.repeat(32),
  iv: '20'.repeat(12),
  aad: 'aabbccdd',
  cleartextSize: 5,
}), undefined);

console.log(`noble-ciphers adapter tests passed (${supported.length} cipher IDs)`);
