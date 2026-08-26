import { createPostQuantumTarget } from './post-quantum-target.mjs';
import { byteSize, cloneCase, compatibleDonor, mutateBytes } from '../mutation.mjs';

const KEM_OPERATIONS = ['KEM_KeyGen', 'KEM_Encapsulate', 'KEM_Decapsulate'];
const SIGNATURE_OPERATIONS = ['PQSIG_KeyGen', 'PQSIG_Sign', 'PQSIG_Verify'];
const PHASE_OPERATIONS = Object.freeze({ general: [...KEM_OPERATIONS, ...SIGNATURE_OPERATIONS], 'slh-dsa': SIGNATURE_OPERATIONS });
const RAW_FIELDS = Object.freeze({
  KEM_KeyGen: ['seed'],
  KEM_Encapsulate: ['publicKey', 'coins'],
  KEM_Decapsulate: ['secretKey', 'cipherText'],
  PQSIG_KeyGen: ['seed'],
  PQSIG_Sign: ['secretKey', 'entropy'],
  PQSIG_Verify: ['publicKey', 'signature'],
});

function algorithmsFor(target, phase, operation) {
  return target.descriptors.filter((info) => {
    if (operation.startsWith('KEM_')) return phase === 'general' && info.kind === 'kem';
    if (phase === 'slh-dsa') return info.family === 'SLH-DSA';
    return info.kind === 'signature' && info.family !== 'SLH-DSA';
  });
}

function patternedBytes(prng, length) {
  const mode = prng.int(6);
  if (mode === 0) return new Uint8Array(length);
  if (mode === 1) return new Uint8Array(length).fill(0xff);
  if (mode === 2) return Uint8Array.from({ length }, (_, index) => index & 0xff);
  return prng.bytes(length);
}

function lengthBucket(length) {
  if (length === 0) return '0';
  const lower = 2 ** Math.floor(Math.log2(length));
  return `${lower}-${2 * lower - 1}`;
}

function makeCase(prng, maxLength, operation, info) {
  const lengths = info.lengths;
  const seedLength = lengths.seed;
  const coinsLength = info.kind === 'kem' ? (lengths.msgRand ?? lengths.msg) : 0;
  const entropyLength = info.kind === 'signature' ? lengths.signRand : 0;
  const fixed = seedLength + coinsLength + entropyLength;
  const candidates = [0, 1, 16, 32, 64, 128, 255, 1024].filter((length) => fixed + length <= maxLength);
  const messageLength = info.kind === 'signature' ? prng.pick(candidates) : 0;
  const contextLength = info.kind === 'signature' && info.family !== 'Falcon' && fixed + messageLength < maxLength
    ? prng.pick([0, 1, 8, 32].filter((length) => fixed + messageLength + length <= maxLength)) : 0;
  return {
    version: 1,
    operation,
    algorithm: info.name,
    seed: patternedBytes(prng, seedLength),
    // Hybrid KEMs use these bytes as a rejection-sampling seed. Degenerate
    // repeated patterns can exhaust the bounded sampler instead of exercising
    // the KEM, so keep coins random and mutate them from valid corpus entries.
    coins: prng.bytes(coinsLength),
    message: patternedBytes(prng, messageLength),
    context: patternedBytes(prng, contextLength),
    entropy: patternedBytes(prng, entropyLength),
  };
}

export function validatePostQuantumCase(testcase, maxLength = 65536, phase) {
  if (testcase?.version !== 1 || !PHASE_OPERATIONS[phase]?.includes(testcase.operation)) throw new Error('invalid post-quantum testcase envelope');
  if (typeof testcase.algorithm !== 'string') throw new Error('invalid post-quantum algorithm');
  for (const field of ['seed', 'coins', 'message', 'context', 'entropy']) {
    if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes`);
  }
  if (testcase.mode !== undefined && testcase.mode !== 'raw') throw new Error('invalid post-quantum testcase mode');
  if (testcase.mode === 'raw') {
    const rawFields = RAW_FIELDS[testcase.operation];
    if (rawFields === undefined) throw new Error(`${testcase.operation} has no raw-input mode`);
    for (const field of rawFields) {
      if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes in raw-input mode`);
    }
    if (testcase.matched !== undefined && typeof testcase.matched !== 'boolean') throw new Error('matched must be boolean');
  }
  if (testcase.context.length > 255) throw new Error('signature context exceeds limit');
  const size = byteSize(testcase);
  if (size > maxLength) throw new Error('testcase exceeds max length');
  if (testcase.algorithm.startsWith('Falcon_') && testcase.context.length !== 0) throw new Error('Falcon does not support contexts');
  return testcase;
}

export const postQuantumProject = {
  name: 'noble-post-quantum',
  packageName: '@noble/post-quantum',
  phases: Object.keys(PHASE_OPERATIONS),
  createTarget: createPostQuantumTarget,
  operations(phase) { return PHASE_OPERATIONS[phase]; },
  chooseOperation(phase, prng) { return prng.pick(PHASE_OPERATIONS[phase]); },
  generateCase(phase, prng, target, maxLength, operation) {
    const testcase = makeCase(prng, maxLength, operation, prng.pick(algorithmsFor(target, phase, operation)));
    if (RAW_FIELDS[operation] !== undefined && prng.bool()) {
      const raw = target.materializeRaw(testcase);
      if (byteSize(raw) <= maxLength) return raw;
    }
    return testcase;
  },
  mutateCase(base, phase, prng, target, maxLength, corpus) {
    if (prng.bool(1, 5)) {
      const operation = prng.pick(PHASE_OPERATIONS[phase]);
      return this.generateCase(phase, prng, target, maxLength, operation);
    }
    let testcase = cloneCase(base);
    if (testcase.mode !== 'raw' && RAW_FIELDS[testcase.operation] !== undefined && prng.bool(1, 3)) {
      const raw = target.materializeRaw(testcase);
      if (byteSize(raw) <= maxLength) testcase = raw;
    }
    if (testcase.mode === 'raw') {
      const fields = [...RAW_FIELDS[testcase.operation], 'message', 'context']
        .filter((field) => testcase[field] instanceof Uint8Array);
      const field = prng.pick(fields);
      const donor = compatibleDonor(corpus, testcase, fields, prng,
        (candidate, current) => candidate.mode === 'raw' && candidate.algorithm === current.algorithm);
      const maximum = maxLength - byteSize(testcase) + testcase[field].length;
      testcase[field] = mutateBytes(testcase[field], prng, maximum, donor?.[field]);
      testcase.matched = false;
      if (testcase.algorithm.startsWith('Falcon_')) testcase.context = new Uint8Array();
      else if (testcase.context.length > 255) testcase.context = testcase.context.subarray(0, 255);
      validatePostQuantumCase(testcase, maxLength, phase);
      return testcase;
    }
    const mutable = ['seed', 'coins', 'message', 'context', 'entropy'].filter((field) => testcase[field].length > 0);
    const field = prng.pick(mutable);
    testcase[field][prng.int(testcase[field].length)] ^= 1 << prng.int(8);
    validatePostQuantumCase(testcase, maxLength, phase);
    return testcase;
  },
  seedCases(phase, prng, target, maxLength) {
    return PHASE_OPERATIONS[phase].flatMap((operation) => algorithmsFor(target, phase, operation).flatMap((info, index) => {
      const testcase = { ...makeCase(prng, maxLength, operation, info), context: new Uint8Array() };
      // A full SLH-DSA lifecycle matrix is already expensive. Seed one raw
      // encoding per operation there; generated cases expand raw coverage to
      // every variant without nearly doubling phase startup time.
      if (RAW_FIELDS[operation] === undefined || (phase === 'slh-dsa' && index !== 0)) return [testcase];
      const raw = target.materializeRaw(testcase);
      return byteSize(raw) <= maxLength ? [testcase, raw] : [testcase];
    }));
  },
  validateCase: validatePostQuantumCase,
  caseFeatures(testcase, target, result) {
    const info = target.algorithms.get(testcase.algorithm);
    return [`op:${testcase.operation}`, `pq:${testcase.algorithm}`, `pq-op:${testcase.operation}:${testcase.algorithm}`,
      `pq-family:${info.family}`,
      `${testcase.algorithm}:message:${testcase.mode === 'raw' ? lengthBucket(testcase.message.length) : testcase.message.length}`,
      `${testcase.algorithm}:context:${testcase.mode === 'raw' ? lengthBucket(testcase.context.length) : testcase.context.length}`,
      `${testcase.algorithm}:seed-zero:${testcase.seed.every((b) => b === 0)}`,
      `${testcase.operation}:mode:${testcase.mode ?? 'lifecycle'}`,
      ...(testcase.mode === 'raw' ? [`${testcase.operation}:raw-source:${testcase.matched === true ? 'matched' : 'mutated'}`] : []),
      ...(testcase.mode === 'raw' ? RAW_FIELDS[testcase.operation].map((field) =>
        `${testcase.operation}:${field}-length:${lengthBucket(testcase[field].length)}`) : []),
      ...(result?.outcome === undefined ? [] : [`${testcase.operation}:raw-outcome:${result.outcome}`])];
  },
  executeCase(target, testcase) { return target.execute(testcase); },
  sampleMask(phase) { return phase === 'slh-dsa' ? 0 : 3; },
  yieldInterval() { return 1; },
};
