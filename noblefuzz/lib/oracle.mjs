import {
  argon2Sync,
  createHash,
  createHmac,
  hkdfSync,
  pbkdf2Sync,
  scryptSync,
} from 'node:crypto';

const nodeHashes = new Map([
  ['MD5', 'md5'],
  ['SHA1', 'sha1'],
  ['SHA224', 'sha224'],
  ['SHA256', 'sha256'],
  ['SHA384', 'sha384'],
  ['SHA512', 'sha512'],
  ['SHA512-224', 'sha512-224'],
  ['SHA512-256', 'sha512-256'],
  ['RIPEMD160', 'ripemd160'],
  ['BLAKE2S256', 'blake2s256'],
  ['BLAKE2B512', 'blake2b512'],
  ['SHA3-224', 'sha3-224'],
  ['SHA3-256', 'sha3-256'],
  ['SHA3-384', 'sha3-384'],
  ['SHA3-512', 'sha3-512'],
  ['SHAKE128', 'shake128'],
  ['SHAKE256', 'shake256'],
  ['SHAKE256-114', 'shake256'],
]);

function nodeHashOptions(testcase) {
  if (testcase.digest === 'SHAKE128') return { outputLength: 16 };
  if (testcase.digest === 'SHAKE256') return { outputLength: 32 };
  if (testcase.digest === 'SHAKE256-114') return { outputLength: 114 };
  return undefined;
}

export function digestOracle(testcase) {
  const name = nodeHashes.get(testcase.digest);
  if (name === undefined) return undefined;
  return createHash(name, nodeHashOptions(testcase)).update(testcase.message).digest();
}

export function hmacOracle(testcase) {
  const name = nodeHashes.get(testcase.digest);
  if (name === undefined || testcase.digest.startsWith('SHAKE')) return undefined;
  return createHmac(name, testcase.key).update(testcase.message).digest();
}

export function hkdfOracle(testcase) {
  const name = nodeHashes.get(testcase.digest);
  if (name === undefined || testcase.digest.startsWith('SHAKE') || testcase.info.length > 1024) return undefined;
  return Buffer.from(hkdfSync(name, testcase.password, testcase.salt, testcase.info, testcase.keySize));
}

export function pbkdf2Oracle(testcase) {
  const name = nodeHashes.get(testcase.digest);
  if (name === undefined || testcase.digest.startsWith('SHAKE')) return undefined;
  return pbkdf2Sync(testcase.password, testcase.salt, testcase.iterations, testcase.keySize, name);
}

export function scryptOracle(testcase) {
  return scryptSync(testcase.password, testcase.salt, testcase.keySize, {
    N: testcase.N,
    r: testcase.r,
    p: testcase.p,
    maxmem: 512 * 1024 * 1024,
  });
}

export function argon2Oracle(testcase) {
  return argon2Sync(['argon2d', 'argon2i', 'argon2id'][testcase.type], {
    message: testcase.password,
    nonce: testcase.salt,
    parallelism: testcase.p,
    tagLength: testcase.keySize,
    memory: testcase.memory,
    passes: testcase.iterations,
  });
}
