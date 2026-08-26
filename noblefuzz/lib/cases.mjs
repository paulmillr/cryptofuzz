const LENGTHS = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256, 511, 512, 1023, 1024, 2048, 4096];
const KEY_LENGTHS = [1, 2, 4, 16, 20, 28, 32, 48, 64, 114, 128, 255, 256, 511, 512, 1023, 1024];

export const PHASE_OPERATIONS = Object.freeze({
  digest: ['Digest'],
  kdfs: ['HMAC', 'HKDF', 'PBKDF2', 'Scrypt'],
  argon2: ['Argon2'],
});

const KDF_OPERATION_BAG = ['HMAC', 'HMAC', 'HMAC', 'HMAC', 'HKDF', 'HKDF', 'PBKDF2', 'PBKDF2', 'Scrypt'];

function boundedLength(prng, maxLength, minimum = 0) {
  const candidates = LENGTHS.filter((length) => length >= minimum && length <= maxLength);
  if (candidates.length === 0) return minimum;
  if (prng.bool(4, 5)) return prng.pick(candidates);
  return minimum + prng.int(Math.max(1, maxLength - minimum + 1));
}

function patternedBytes(prng, length) {
  const mode = prng.int(8);
  if (mode === 0) return new Uint8Array(length);
  if (mode === 1) return new Uint8Array(length).fill(0xff);
  if (mode === 2) return new Uint8Array(length).fill(prng.next() & 0xff);
  if (mode === 3) return Uint8Array.from({ length }, (_, index) => index & 0xff);
  if (mode === 4) return Uint8Array.from({ length }, (_, index) => 0x61 + (index % 26));
  return prng.bytes(length);
}

function chunksFor(prng, length) {
  if (length === 0) return prng.bool() ? [0] : [0, 0];
  if (prng.bool(1, 3)) return [length];
  const chunks = [];
  let remaining = length;
  const wanted = 2 + prng.int(Math.min(8, length + 1));
  for (let index = 0; index < wanted - 1; index++) {
    if (prng.bool(1, 5)) chunks.push(0);
    if (remaining === 0) continue;
    const lengthHere = prng.int(remaining + 1);
    chunks.push(lengthHere);
    remaining -= lengthHere;
  }
  chunks.push(remaining);
  if (prng.bool(1, 5)) chunks.push(0);
  return chunks;
}

function digestCase(prng, algorithms, maxLength, digest = prng.pick(algorithms)) {
  const message = patternedBytes(prng, boundedLength(prng, maxLength));
  return { version: 1, operation: 'Digest', digest, message, chunks: chunksFor(prng, message.length) };
}

function hmacCase(prng, algorithms, maxLength, digest = prng.pick(algorithms)) {
  const messageLength = boundedLength(prng, Math.max(0, maxLength - 1));
  const keyLength = boundedLength(prng, Math.max(1, maxLength - messageLength), 1);
  const message = patternedBytes(prng, messageLength);
  return {
    version: 1,
    operation: 'HMAC',
    digest,
    message,
    chunks: chunksFor(prng, message.length),
    key: patternedBytes(prng, keyLength),
  };
}

function hkdfCase(prng, algorithms, maxLength, digest = prng.pick(algorithms)) {
  const fieldLimit = Math.max(1, Math.floor(maxLength / 3));
  return {
    version: 1,
    operation: 'HKDF',
    digest,
    password: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    salt: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    info: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    keySize: prng.pick(KEY_LENGTHS.filter((length) => length <= Math.min(1024, maxLength))),
  };
}

function pbkdf2Case(prng, algorithms, maxLength, digest = prng.pick(algorithms)) {
  const fieldLimit = Math.max(1, Math.floor(maxLength / 2));
  return {
    version: 1,
    operation: 'PBKDF2',
    digest,
    password: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    salt: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    iterations: prng.pick([1, 2, 3, 4, 8, 16, 32]),
    keySize: prng.pick(KEY_LENGTHS.filter((length) => length <= Math.min(1024, maxLength))),
  };
}

function scryptCase(prng, maxLength) {
  const fieldLimit = Math.max(1, Math.floor(maxLength / 2));
  const r = prng.pick([1, 2, 4, 8]);
  const maximumN = Math.min(16384, 2 ** Math.max(1, Math.floor(Math.log2(262144 / r))));
  const nValues = [2, 16, 256, 1024, 4096, 16384].filter((value) => value <= maximumN);
  return {
    version: 1,
    operation: 'Scrypt',
    password: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    salt: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    N: prng.pick(nValues),
    r,
    p: 1 + prng.int(4),
    keySize: prng.pick(KEY_LENGTHS.filter((length) => length <= Math.min(1024, maxLength))),
  };
}

function argon2Case(prng, maxLength) {
  const p = 1 + prng.int(4);
  const fieldLimit = Math.max(8, Math.floor(maxLength / 2));
  const memory = prng.pick([8 * p, 32, 64, 256, 1024, 4096, 16384, 65536].filter((value) => value >= 8 * p));
  return {
    version: 1,
    operation: 'Argon2',
    type: prng.int(3),
    password: patternedBytes(prng, boundedLength(prng, fieldLimit)),
    salt: patternedBytes(prng, boundedLength(prng, fieldLimit, 8)),
    iterations: 1 + prng.int(3),
    memory,
    p,
    keySize: prng.pick(KEY_LENGTHS.filter((length) => length >= 4 && length <= Math.min(1024, maxLength))),
  };
}

export function generateCase(phase, prng, algorithms, maxLength, forcedOperation) {
  const operation = forcedOperation ?? (phase === 'kdfs' ? prng.pick(KDF_OPERATION_BAG) : PHASE_OPERATIONS[phase]?.[0]);
  if (operation === undefined) throw new Error(`unknown phase ${phase}`);
  if (operation === 'Digest') return digestCase(prng, algorithms, maxLength);
  if (operation === 'HMAC') return hmacCase(prng, algorithms, maxLength);
  if (operation === 'HKDF') return hkdfCase(prng, algorithms, maxLength);
  if (operation === 'PBKDF2') return pbkdf2Case(prng, algorithms, maxLength);
  if (operation === 'Scrypt') return scryptCase(prng, maxLength);
  if (operation === 'Argon2') return argon2Case(prng, maxLength);
  throw new Error(`unknown operation ${operation}`);
}

function mutateBytes(bytes, prng, maxLength) {
  let result = Uint8Array.from(bytes);
  const action = prng.int(7);
  if (action <= 2 && result.length > 0) {
    const index = prng.int(result.length);
    result[index] ^= 1 << prng.int(8);
  } else if (action === 3 && result.length > 0) {
    result[prng.int(result.length)] = prng.next() & 0xff;
  } else if (action === 4 && result.length > 0) {
    const index = prng.int(result.length);
    result = Uint8Array.from([...result.subarray(0, index), ...result.subarray(index + 1)]);
  } else if (action === 5 && result.length < maxLength) {
    const index = prng.int(result.length + 1);
    result = Uint8Array.from([...result.subarray(0, index), prng.next() & 0xff, ...result.subarray(index)]);
  } else {
    result = patternedBytes(prng, boundedLength(prng, maxLength));
  }
  return result;
}

export function mutateCase(base, phase, prng, algorithms, maxLength) {
  if (base === undefined || prng.bool(1, 5)) return generateCase(phase, prng, algorithms, maxLength);
  const testcase = Object.fromEntries(Object.entries(base).map(([key, value]) => {
    if (value instanceof Uint8Array) return [key, Uint8Array.from(value)];
    if (Array.isArray(value)) return [key, value.slice()];
    return [key, value];
  }));
  if (testcase.digest !== undefined && prng.bool(1, 8)) testcase.digest = prng.pick(algorithms);

  const byteFields = ['message', 'key', 'password', 'salt', 'info'].filter((field) => testcase[field] !== undefined);
  if (byteFields.length > 0) {
    const field = prng.pick(byteFields);
    const otherSize = byteFields.reduce((size, name) => name === field ? size : size + testcase[name].length, 0);
    const minimum = field === 'salt' && testcase.operation === 'Argon2' ? 8 : 0;
    testcase[field] = mutateBytes(testcase[field], prng, Math.max(minimum, maxLength - otherSize));
    if (testcase[field].length < minimum) testcase[field] = patternedBytes(prng, minimum);
  }

  if (testcase.message !== undefined) testcase.chunks = chunksFor(prng, testcase.message.length);
  if (testcase.operation === 'PBKDF2') testcase.iterations = prng.pick([1, 2, 3, 4, 8, 16, 32]);
  if (testcase.operation === 'Scrypt') {
    testcase.N = prng.pick([2, 16, 256, 1024, 4096, 16384]);
    testcase.r = prng.pick([1, 2, 4, 8]);
    testcase.p = 1 + prng.int(4);
  }
  if (testcase.operation === 'Argon2') {
    testcase.type = prng.int(3);
    testcase.p = 1 + prng.int(4);
    testcase.iterations = 1 + prng.int(3);
    testcase.memory = prng.pick([8 * testcase.p, 32, 64, 256, 1024, 4096, 16384, 65536]
      .filter((value) => value >= 8 * testcase.p));
  }
  if ('keySize' in testcase && prng.bool(1, 3)) {
    const maximum = 1024;
    const minimum = testcase.operation === 'Argon2' ? 4 : 1;
    testcase.keySize = prng.pick(KEY_LENGTHS.filter((length) => length >= minimum && length <= Math.min(maximum, maxLength)));
  }
  validateCase(testcase, maxLength, phase);
  return testcase;
}

function encodeValue(value) {
  if (value instanceof Uint8Array) return { $bytes: Buffer.from(value).toString('base64') };
  if (Array.isArray(value)) return value.map(encodeValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, encodeValue(child)]));
  }
  return value;
}

function decodeValue(value) {
  if (value !== null && typeof value === 'object' && Object.keys(value).length === 1 && typeof value.$bytes === 'string') {
    return Uint8Array.from(Buffer.from(value.$bytes, 'base64'));
  }
  if (Array.isArray(value)) return value.map(decodeValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, decodeValue(child)]));
  }
  return value;
}

export function encodeCase(testcase) {
  return `${JSON.stringify(encodeValue(testcase))}\n`;
}

export function decodeCase(serialized) {
  return decodeValue(JSON.parse(serialized));
}

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
}

export function validateCase(testcase, maxLength = 4096, phase) {
  if (testcase?.version !== 1 || typeof testcase.operation !== 'string') throw new Error('invalid testcase envelope');
  if (phase !== undefined && !PHASE_OPERATIONS[phase]?.includes(testcase.operation)) {
    throw new Error(`${testcase.operation} does not belong to ${phase}`);
  }
  const byteFields = ['message', 'key', 'password', 'salt', 'info'].filter((field) => testcase[field] !== undefined);
  for (const field of byteFields) {
    if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes`);
  }
  if (byteFields.reduce((size, field) => size + testcase[field].length, 0) > maxLength) {
    throw new Error(`testcase exceeds max length ${maxLength}`);
  }
  if (testcase.operation === 'Digest' || testcase.operation === 'HMAC') {
    if (typeof testcase.digest !== 'string' || !Array.isArray(testcase.chunks)) throw new Error('invalid hash testcase');
    if (testcase.chunks.some((length) => !Number.isSafeInteger(length) || length < 0)) throw new Error('invalid chunks');
    if (testcase.chunks.reduce((sum, length) => sum + length, 0) !== testcase.message.length) {
      throw new Error('chunks do not cover message');
    }
  }
  if (testcase.operation === 'HKDF' || testcase.operation === 'PBKDF2') {
    if (typeof testcase.digest !== 'string') throw new Error('invalid KDF digest');
  }
  if ('keySize' in testcase) positiveInteger(testcase.keySize, 'keySize');
  if (testcase.keySize > 1024) throw new Error('keySize exceeds the fuzzing limit');
  if (testcase.operation === 'PBKDF2') {
    positiveInteger(testcase.iterations, 'iterations');
    if (testcase.iterations > 32) throw new Error('PBKDF2 iterations exceed the fuzzing limit');
  }
  if (testcase.operation === 'Scrypt') {
    positiveInteger(testcase.N, 'N');
    positiveInteger(testcase.r, 'r');
    positiveInteger(testcase.p, 'p');
    if ((testcase.N & (testcase.N - 1)) !== 0 || testcase.N > 16384 || testcase.r > 8 || testcase.p > 4) {
      throw new Error('invalid scrypt parameters');
    }
  }
  if (testcase.operation === 'Argon2') {
    if (![0, 1, 2].includes(testcase.type)) throw new Error('invalid Argon2 type');
    positiveInteger(testcase.p, 'p');
    positiveInteger(testcase.memory, 'memory');
    positiveInteger(testcase.iterations, 'iterations');
    if (testcase.keySize < 4) throw new Error('Argon2 keySize must be at least 4');
    if (
      testcase.p > 4 || testcase.memory < 8 * testcase.p || testcase.memory > 65536 ||
      testcase.iterations > 3 || testcase.salt.length < 8
    ) {
      throw new Error('invalid Argon2 parameters');
    }
  }
  return testcase;
}

export function seedCases(phase, prng, algorithms, maxLength) {
  if (phase === 'digest') {
    return algorithms.flatMap((digest, index) => {
      const testcase = digestCase(prng, algorithms, maxLength, digest);
      const boundaryLength = LENGTHS[index % LENGTHS.length];
      testcase.message = patternedBytes(prng, Math.min(maxLength, boundaryLength));
      testcase.chunks = chunksFor(prng, testcase.message.length);
      return [testcase];
    });
  }
  if (phase === 'kdfs') {
    const cases = [];
    for (const digest of algorithms) {
      cases.push(hmacCase(prng, algorithms, maxLength, digest));
      cases.push(hkdfCase(prng, algorithms, maxLength, digest));
      cases.push(pbkdf2Case(prng, algorithms, maxLength, digest));
    }
    for (let p = 1; p <= 4; p++) cases.push({ ...scryptCase(prng, maxLength), p });
    return cases;
  }
  if (phase === 'argon2') {
    const cases = [];
    for (let type = 0; type < 3; type++) {
      for (let p = 1; p <= 4; p++) {
        const testcase = argon2Case(prng, maxLength);
        testcase.type = type;
        testcase.p = p;
        testcase.memory = Math.max(testcase.memory, 8 * p);
        cases.push(testcase);
      }
    }
    return cases;
  }
  throw new Error(`unknown phase ${phase}`);
}

function lengthBucket(length) {
  if (length === 0) return '0';
  return `${2 ** Math.floor(Math.log2(length))}-${2 ** (Math.floor(Math.log2(length)) + 1) - 1}`;
}

export function caseFeatures(testcase, target) {
  const features = [`op:${testcase.operation}`];
  if (testcase.digest !== undefined) features.push(`digest:${testcase.operation}:${testcase.digest}`);
  const scope = testcase.digest === undefined ? testcase.operation : `${testcase.operation}:${testcase.digest}`;
  for (const field of ['message', 'key', 'password', 'salt', 'info']) {
    const bytes = testcase[field];
    if (bytes === undefined) continue;
    features.push(`${scope}:${field}:len:${lengthBucket(bytes.length)}`);
    if (bytes.length > 0 && bytes.every((byte) => byte === 0)) features.push(`${scope}:${field}:all-zero`);
    if (bytes.length > 0 && bytes.every((byte) => byte === 0xff)) features.push(`${scope}:${field}:all-ff`);
  }
  if (testcase.chunks !== undefined) {
    features.push(`${scope}:chunks:${lengthBucket(testcase.chunks.length)}`);
    if (testcase.chunks.includes(0)) features.push(`${scope}:empty-chunk`);
    const { blockLen } = target.hashInfo(testcase.digest, testcase.operation === 'HMAC');
    if (testcase.message.length % blockLen === 0) features.push(`${scope}:block:exact`);
    if (testcase.message.length % blockLen === 1) features.push(`${scope}:block:plus-one`);
    if (testcase.message.length % blockLen === blockLen - 1) features.push(`${scope}:block:minus-one`);
  }
  for (const field of ['keySize', 'iterations', 'N', 'r', 'p', 'memory', 'type']) {
    if (testcase[field] !== undefined) features.push(`${scope}:${field}:${testcase[field]}`);
  }
  if (testcase.operation === 'Scrypt') features.push(`Scrypt:params:${testcase.N}:${testcase.r}:${testcase.p}`);
  if (testcase.operation === 'Argon2') features.push(`Argon2:params:${testcase.type}:${testcase.p}:${lengthBucket(testcase.memory)}:${testcase.iterations}`);
  return features;
}
