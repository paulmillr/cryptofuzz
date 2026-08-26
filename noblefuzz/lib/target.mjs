import { packageImporter } from './package-importer.mjs';

function configuredHash(hash, options) {
  const configured = (message) => hash(message, options);
  const instance = hash.create(options);
  configured.outputLen = instance.outputLen;
  configured.blockLen = instance.blockLen;
  configured.create = () => hash.create(options);
  return configured;
}

function joinParts(message, cuts) {
  const parts = [];
  let offset = 0;
  for (const length of cuts) {
    parts.push(message.subarray(offset, offset + length));
    offset += length;
  }
  if (offset !== message.length) throw new Error('chunk lengths do not cover the message');
  return parts;
}

function knownAnswer(actual, expectedHex, label) {
  const expected = Buffer.from(expectedHex, 'hex');
  if (!Buffer.from(actual).equals(expected)) throw new Error(`${label} known-answer mismatch`);
}

export async function createTarget(sourceDirectory = process.env.NOBLE_SOURCE_DIR) {
  const load = await packageImporter('@noble/hashes', sourceDirectory);
  const [blake2, blake3Module, argon2, hkdfModule, hmacModule, legacy, pbkdf2Module, scryptModule, sha2, sha3] =
    await Promise.all([
      load('blake2.js'),
      load('blake3.js'),
      load('argon2.js'),
      load('hkdf.js'),
      load('hmac.js'),
      load('legacy.js'),
      load('pbkdf2.js'),
      load('scrypt.js'),
      load('sha2.js'),
      load('sha3.js'),
    ]);

  // Node/OpenSSL does not expose BLAKE3, so one-shot/streaming agreement alone
  // could let both paths share the same broken compression function.
  knownAnswer(blake3Module.blake3(new Uint8Array()),
    'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262', 'BLAKE3 empty input');

  const hashes = new Map([
    ['MD5', legacy.md5],
    ['SHA1', legacy.sha1],
    ['SHA224', sha2.sha224],
    ['SHA256', sha2.sha256],
    ['SHA384', sha2.sha384],
    ['SHA512', sha2.sha512],
    ['SHA512-224', sha2.sha512_224],
    ['SHA512-256', sha2.sha512_256],
    ['RIPEMD160', legacy.ripemd160],
    ['BLAKE2S128', configuredHash(blake2.blake2s, { dkLen: 16 })],
    ['BLAKE2S160', configuredHash(blake2.blake2s, { dkLen: 20 })],
    ['BLAKE2S224', configuredHash(blake2.blake2s, { dkLen: 28 })],
    ['BLAKE2S256', blake2.blake2s],
    ['BLAKE2B128', configuredHash(blake2.blake2b, { dkLen: 16 })],
    ['BLAKE2B160', configuredHash(blake2.blake2b, { dkLen: 20 })],
    ['BLAKE2B256', configuredHash(blake2.blake2b, { dkLen: 32 })],
    ['BLAKE2B384', configuredHash(blake2.blake2b, { dkLen: 48 })],
    ['BLAKE2B512', blake2.blake2b],
    ['BLAKE3', blake3Module.blake3],
    ['SHA3-224', sha3.sha3_224],
    ['SHA3-256', sha3.sha3_256],
    ['SHA3-384', sha3.sha3_384],
    ['SHA3-512', sha3.sha3_512],
    ['KECCAK-224', sha3.keccak_224],
    ['KECCAK-256', sha3.keccak_256],
    ['KECCAK-384', sha3.keccak_384],
    ['KECCAK-512', sha3.keccak_512],
    ['SHAKE128', configuredHash(sha3.shake128, { dkLen: 16 })],
    ['SHAKE256', configuredHash(sha3.shake256, { dkLen: 32 })],
    ['SHAKE256-114', configuredHash(sha3.shake256, { dkLen: 114 })],
  ]);
  const kdfHashes = new Map(hashes);
  kdfHashes.set('SHAKE128', configuredHash(sha3.shake128, { dkLen: 32 }));
  kdfHashes.set('SHAKE256', configuredHash(sha3.shake256, { dkLen: 64 }));

  function getHash(name, kdf = false) {
    const hash = (kdf ? kdfHashes : hashes).get(name);
    if (hash === undefined) throw new Error(`unsupported digest ${name}`);
    return hash;
  }

  return {
    algorithms: [...hashes.keys()],
    hashInfo(name, kdf = false) {
      const hash = getHash(name, kdf);
      return { outputLen: hash.outputLen, blockLen: hash.blockLen };
    },
    digest(testcase) {
      const hash = getHash(testcase.digest);
      const direct = hash(testcase.message);
      const streaming = hash.create();
      for (const part of joinParts(testcase.message, testcase.chunks)) streaming.update(part);
      return { direct, streaming: streaming.digest() };
    },
    hmac(testcase) {
      const hash = getHash(testcase.digest, true);
      const direct = hmacModule.hmac(hash, testcase.key, testcase.message);
      const streaming = hmacModule.hmac.create(hash, testcase.key);
      for (const part of joinParts(testcase.message, testcase.chunks)) streaming.update(part);
      return { direct, streaming: streaming.digest() };
    },
    hkdf(testcase) {
      return hkdfModule.hkdf(
        getHash(testcase.digest, true),
        testcase.password,
        testcase.salt,
        testcase.info,
        testcase.keySize,
      );
    },
    pbkdf2(testcase) {
      return pbkdf2Module.pbkdf2(
        getHash(testcase.digest, true),
        testcase.password,
        testcase.salt,
        { c: testcase.iterations, dkLen: testcase.keySize },
      );
    },
    scrypt(testcase) {
      return scryptModule.scrypt(testcase.password, testcase.salt, {
        N: testcase.N,
        r: testcase.r,
        p: testcase.p,
        dkLen: testcase.keySize,
        maxmem: 512 * 1024 * 1024,
      });
    },
    argon2(testcase) {
      const algorithm = [argon2.argon2d, argon2.argon2i, argon2.argon2id][testcase.type];
      if (algorithm === undefined) throw new Error(`unsupported Argon2 type ${testcase.type}`);
      return algorithm(testcase.password, testcase.salt, {
        t: testcase.iterations,
        m: testcase.memory,
        p: testcase.p,
        dkLen: testcase.keySize,
        maxmem: 512 * 1024 * 1024,
      });
    },
  };
}
