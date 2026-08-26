import { CIPHER_SPECS, createCiphersTarget } from './ciphers-target.mjs';
import { byteSize, cloneCase, compatibleDonor, mutateBytes as mutateRawBytes } from '../mutation.mjs';

const LENGTHS = [0, 1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 2048, 4096];
const SPECS = new Map(CIPHER_SPECS.map((spec) => [spec.name, spec]));

function boundedLength(prng, maximum) {
  const candidates = LENGTHS.filter((length) => length <= maximum);
  return prng.bool(4, 5) ? prng.pick(candidates) : prng.int(maximum + 1);
}

function patternedBytes(prng, length) {
  const mode = prng.int(7);
  if (mode === 0) return new Uint8Array(length);
  if (mode === 1) return new Uint8Array(length).fill(0xff);
  if (mode === 2) return new Uint8Array(length).fill(prng.next() & 0xff);
  if (mode === 3) return Uint8Array.from({ length }, (_, index) => index & 0xff);
  return prng.bytes(length);
}

function dataLength(prng, spec, maximum, operation) {
  if (operation === 'SymmetricDecrypt') {
    if (spec.kind === 'cbc') return 16 * (1 + prng.int(Math.max(1, Math.floor(maximum / 16))));
    if (spec.kind === 'aeskw') return 24 + 8 * prng.int(Math.max(1, Math.floor((maximum - 24) / 8) + 1));
    if (spec.kind === 'aeskwp') return 16 + 8 * prng.int(Math.max(1, Math.floor((maximum - 16) / 8) + 1));
    if (spec.aead) return 16 + boundedLength(prng, Math.max(0, maximum - 16));
  }
  if (spec.kind === 'ecb') return 16 * prng.int(Math.floor(maximum / 16) + 1);
  if (spec.kind === 'aeskw') {
    if (maximum < 16) return 16;
    return 16 + 8 * prng.int(Math.floor((maximum - 16) / 8) + 1);
  }
  if (spec.kind === 'aeskwp') return 1 + prng.int(Math.max(1, maximum));
  return boundedLength(prng, maximum);
}

function minimumDataLength(spec, operation) {
  if (operation === 'SymmetricDecrypt') {
    if (spec.kind === 'cbc') return 16;
    if (spec.kind === 'aeskw') return 24;
    if (spec.kind === 'aeskwp' || spec.aead) return 16;
    return 0;
  }
  if (spec.kind === 'aeskw') return 16;
  if (spec.kind === 'aeskwp') return 1;
  return 0;
}

function makeCase(prng, maxLength, selected, operation) {
  const spec = typeof selected === 'string' ? SPECS.get(selected) : selected;
  const ivLength = spec.ivLengths === undefined ? spec.ivLength : prng.pick(spec.ivLengths);
  const aadMaximum = spec.aead ? Math.min(256, Math.max(0, maxLength - spec.keyLength - ivLength)) : 0;
  const aadLength = spec.aead ? boundedLength(prng, aadMaximum) : 0;
  const available = Math.max(minimumDataLength(spec, operation),
    maxLength - spec.keyLength - ivLength - aadLength);
  return {
    version: 1,
    operation,
    cipher: spec.name,
    key: patternedBytes(prng, spec.keyLength),
    iv: patternedBytes(prng, ivLength),
    aad: patternedBytes(prng, aadLength),
    data: patternedBytes(prng, dataLength(prng, spec, available, operation)),
  };
}

function clone(testcase) {
  return Object.fromEntries(Object.entries(testcase).map(([key, value]) =>
    [key, value instanceof Uint8Array ? Uint8Array.from(value) : value]));
}

function mutateBytes(value, prng) {
  const result = Uint8Array.from(value);
  if (result.length > 0 && prng.bool(4, 5)) result[prng.int(result.length)] ^= 1 << prng.int(8);
  else if (result.length > 0) result.fill(prng.next() & 0xff);
  return result;
}

function lengthBucket(length) {
  if (length === 0) return '0';
  const lower = 2 ** Math.floor(Math.log2(length));
  return `${lower}-${2 * lower - 1}`;
}

export function validateCipherCase(testcase, maxLength = 4096, phase) {
  if (phase !== undefined && phase !== 'ciphers') throw new Error(`Cipher does not belong to ${phase}`);
  if (testcase?.version !== 1 || !['SymmetricEncrypt', 'SymmetricDecrypt'].includes(testcase.operation)) {
    throw new Error('invalid cipher testcase envelope');
  }
  const spec = SPECS.get(testcase.cipher);
  if (spec === undefined) throw new Error(`unsupported cipher ${JSON.stringify(testcase.cipher)}`);
  for (const field of ['key', 'iv', 'aad', 'data']) {
    if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes`);
  }
  if (testcase.mode !== undefined && testcase.mode !== 'raw') throw new Error('invalid cipher testcase mode');
  if (testcase.mode === 'raw' && testcase.matched !== undefined && typeof testcase.matched !== 'boolean') {
    throw new Error('matched must be boolean');
  }
  if (byteSize(testcase) > maxLength) throw new Error(`testcase exceeds max length ${maxLength}`);
  if (testcase.mode === 'raw') return testcase;
  if (testcase.key.length !== spec.keyLength) throw new Error('invalid cipher key length');
  if (spec.ivLengths !== undefined) {
    if (!spec.ivLengths.includes(testcase.iv.length)) throw new Error('invalid cipher IV length');
  } else if (testcase.iv.length !== spec.ivLength) throw new Error('invalid cipher IV length');
  if (!spec.aead && testcase.aad.length !== 0) throw new Error('AAD supplied to a non-AEAD cipher');
  if (spec.kind === 'ecb' && testcase.data.length % 16 !== 0) throw new Error('invalid ECB data length');
  if (spec.kind === 'cbc' && testcase.operation === 'SymmetricDecrypt' &&
      (testcase.data.length === 0 || testcase.data.length % 16 !== 0)) throw new Error('invalid CBC ciphertext length');
  const kwMinimum = testcase.operation === 'SymmetricDecrypt' ? 24 : 16;
  if (spec.kind === 'aeskw' && (testcase.data.length < kwMinimum || testcase.data.length % 8 !== 0)) {
    throw new Error('invalid AES-KW data length');
  }
  if (spec.kind === 'aeskwp') {
    if (testcase.operation === 'SymmetricEncrypt' && testcase.data.length === 0) throw new Error('invalid AES-KWP data length');
    if (testcase.operation === 'SymmetricDecrypt' && (testcase.data.length < 16 || testcase.data.length % 8 !== 0)) {
      throw new Error('invalid AES-KWP ciphertext length');
    }
  }
  if (spec.aead && testcase.operation === 'SymmetricDecrypt' && testcase.data.length < 16) {
    throw new Error('authenticated ciphertext is shorter than its tag');
  }
  return testcase;
}

export const ciphersProject = {
  name: 'noble-ciphers',
  packageName: '@noble/ciphers',
  phases: ['ciphers'],
  createTarget: createCiphersTarget,
  operations() {
    return ['SymmetricEncrypt', 'SymmetricDecrypt'];
  },
  chooseOperation(phase, prng) {
    return prng.bool() ? 'SymmetricEncrypt' : 'SymmetricDecrypt';
  },
  generateCase(phase, prng, target, maxLength, operation) {
    const testcase = makeCase(prng, maxLength, prng.pick(target.specs), operation);
    return prng.bool(1, 3) ? { ...testcase, mode: 'raw', matched: true } : testcase;
  },
  mutateCase(base, phase, prng, target, maxLength, corpus) {
    if (prng.bool(1, 6)) {
      const operation = prng.bool() ? 'SymmetricEncrypt' : 'SymmetricDecrypt';
      return makeCase(prng, maxLength, prng.pick(target.specs), operation);
    }
    const testcase = base.mode === 'raw' ? cloneCase(base) : clone(base);
    const field = prng.pick(['key', 'iv', 'aad', 'data']);
    if (testcase.mode === 'raw') {
      const donor = compatibleDonor(corpus, testcase, ['key', 'iv', 'aad', 'data'], prng,
        (candidate, current) => candidate.mode === 'raw' && candidate.cipher === current.cipher);
      const maximum = maxLength - byteSize(testcase) + testcase[field].length;
      testcase[field] = mutateRawBytes(testcase[field], prng, maximum, donor?.[field]);
      testcase.matched = false;
    } else {
      testcase[field] = mutateBytes(testcase[field], prng);
    }
    validateCipherCase(testcase, maxLength, phase);
    return testcase;
  },
  seedCases(phase, prng, target, maxLength) {
    return this.operations().flatMap((operation) => target.specs.flatMap((spec) => {
      const testcase = makeCase(prng, maxLength, spec, operation);
      return [testcase, { ...testcase, mode: 'raw', matched: true }];
    }));
  },
  validateCase: validateCipherCase,
  caseFeatures(testcase, target, result) {
    const spec = target.spec(testcase.cipher);
    const features = [
      `op:${testcase.operation}`, `cipher:${testcase.cipher}`, `cipher-kind:${spec.kind}`,
      `cipher-op:${testcase.operation}:${testcase.cipher}`,
      `${testcase.operation}:mode:${testcase.mode ?? 'valid-shape'}`,
    ];
    if (testcase.mode === 'raw') {
      features.push(`${testcase.operation}:raw-source:${testcase.matched === true ? 'matched' : 'mutated'}`);
      for (const field of ['key', 'iv', 'aad', 'data']) {
        features.push(`${testcase.operation}:raw:${field}-length:${lengthBucket(testcase[field].length)}`);
      }
      if (result?.outcome !== undefined) features.push(`${testcase.operation}:${testcase.cipher}:raw-outcome:${result.outcome}`);
      if (testcase.data.length % 16 === 0) features.push(`${testcase.operation}:raw:block:exact`);
      if (testcase.data.length > 0 && testcase.data.every((byte) => byte === 0)) {
        features.push(`${testcase.operation}:raw:data:all-zero`);
      }
    } else {
      features.push(`${testcase.cipher}:data:${lengthBucket(testcase.data.length)}`,
        `${testcase.cipher}:aad:${lengthBucket(testcase.aad.length)}`, `${testcase.cipher}:iv:${testcase.iv.length}`);
      if (testcase.data.length % 16 === 0) features.push(`${testcase.cipher}:block:exact`);
      if (testcase.data.length > 0 && testcase.data.every((byte) => byte === 0)) {
        features.push(`${testcase.cipher}:data:all-zero`);
      }
    }
    return features;
  },
  executeCase(target, testcase) {
    return target.execute(testcase);
  },
  sampleMask() {
    return 31;
  },
  yieldInterval() {
    return 128;
  },
};
