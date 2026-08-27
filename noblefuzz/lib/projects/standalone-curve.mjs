import { byteSize, cloneCase, compatibleDonor, mutateBytes } from '../mutation.mjs';

const LENGTHS = [0, 1, 2, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 511, 512, 1024, 2048];

function patternedBytes(prng, length) {
  const mode = prng.int(7);
  if (mode === 0) return new Uint8Array(length);
  if (mode === 1) return new Uint8Array(length).fill(0xff);
  if (mode === 2) return new Uint8Array(length).fill(prng.next() & 0xff);
  if (mode === 3) return Uint8Array.from({ length }, (_, index) => index & 0xff);
  return prng.bytes(length);
}

function boundedLength(prng, maximum) {
  const candidates = LENGTHS.filter((length) => length <= maximum);
  if (candidates.length > 0 && prng.bool(4, 5)) return prng.pick(candidates);
  return prng.int(maximum + 1);
}

function lengthBucket(length) {
  if (length === 0) return '0';
  const lower = 2 ** Math.floor(Math.log2(length));
  return `${lower}-${2 * lower - 1}`;
}

export function createStandaloneCurveProject({
  name,
  packageName,
  operations,
  rawFields,
  fixedMessageOperations = [],
  createTarget,
}) {
  const fixedMessages = new Set(fixedMessageOperations);
  const makeCase = (prng, maxLength, operation = prng.pick(operations)) => {
    const fixedBytes = 96;
    if (maxLength < fixedBytes) throw new Error(`${name} requires --max-len >= ${fixedBytes}`);
    const messageCapacity = maxLength - fixedBytes;
    if (fixedMessages.has(operation) && messageCapacity < 32) {
      throw new Error(`${name} requires --max-len >= ${fixedBytes + 32} for ${operation}`);
    }
    const messageLength = fixedMessages.has(operation) ? 32 : boundedLength(prng, messageCapacity);
    return {
      version: 1,
      operation,
      secretA: patternedBytes(prng, 32),
      secretB: patternedBytes(prng, 32),
      aux: patternedBytes(prng, 32),
      message: patternedBytes(prng, messageLength),
    };
  };

  const validateCase = (testcase, maxLength = 4096, phase) => {
    if (phase !== undefined && phase !== 'fast') throw new Error(`${name} has no ${phase} phase`);
    if (testcase?.version !== 1 || !operations.includes(testcase.operation)) {
      throw new Error(`invalid ${name} testcase envelope`);
    }
    for (const field of ['secretA', 'secretB', 'aux', 'message']) {
      if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes`);
    }
    for (const field of ['secretA', 'secretB']) {
      if (testcase[field].length !== 32) throw new Error(`${field} must contain 32 bytes`);
    }
    if (testcase.aux.length !== 32 && (testcase.mode !== 'raw' || !rawFields[testcase.operation].includes('aux'))) {
      throw new Error('aux must contain 32 bytes');
    }
    if (fixedMessages.has(testcase.operation) && testcase.message.length !== 32) {
      throw new Error(`${testcase.operation} message must contain 32 bytes`);
    }
    if (testcase.mode !== undefined && testcase.mode !== 'raw') throw new Error('invalid standalone curve mode');
    if (testcase.mode === 'raw') {
      for (const field of rawFields[testcase.operation]) {
        if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes in raw-input mode`);
      }
      if (testcase.matched !== undefined && typeof testcase.matched !== 'boolean') {
        throw new Error('matched must be boolean');
      }
    }
    if (byteSize(testcase) > maxLength) throw new Error('testcase exceeds max length');
    return testcase;
  };

  return {
    name,
    packageName,
    phases: ['fast'],
    createTarget,
    operations(phase) {
      if (phase !== 'fast') throw new Error(`${name} has no ${phase} phase`);
      return operations;
    },
    chooseOperation(phase, prng) { return prng.pick(this.operations(phase)); },
    generateCase(phase, prng, target, maxLength, operation) {
      const testcase = makeCase(prng, maxLength, operation);
      if (prng.bool()) {
        const raw = target.materializeRaw(testcase);
        if (byteSize(raw) <= maxLength) return raw;
      }
      return testcase;
    },
    mutateCase(base, phase, prng, target, maxLength, corpus) {
      if (prng.bool(1, 5)) return makeCase(prng, maxLength, prng.pick(this.operations(phase)));
      let testcase = cloneCase(base);
      if (testcase.mode !== 'raw' && prng.bool(1, 3)) {
        const raw = target.materializeRaw(testcase);
        if (byteSize(raw) <= maxLength) testcase = raw;
      }
      if (testcase.mode === 'raw') {
        const fields = [...rawFields[testcase.operation], 'message'];
        const field = prng.pick(fields);
        const donor = compatibleDonor(corpus, testcase, fields, prng,
          (candidate, current) => candidate.mode === 'raw' && candidate.operation === current.operation);
        const maximum = maxLength - byteSize(testcase) + testcase[field].length;
        testcase[field] = mutateBytes(testcase[field], prng, maximum, donor?.[field]);
        testcase.matched = false;
        if (fixedMessages.has(testcase.operation) && testcase.message.length !== 32) {
          testcase.message = patternedBytes(prng, 32);
        }
      } else {
        const fields = ['secretA', 'secretB', 'aux', 'message'];
        const field = prng.pick(fields);
        if (field === 'message' && !fixedMessages.has(testcase.operation)) {
          const maximum = maxLength - byteSize(testcase) + testcase.message.length;
          testcase.message = mutateBytes(testcase.message, prng, maximum);
        } else if (testcase[field].length > 0) {
          testcase[field][prng.int(testcase[field].length)] ^= 1 << prng.int(8);
        }
      }
      validateCase(testcase, maxLength, phase);
      return testcase;
    },
    seedCases(phase, prng, target, maxLength) {
      const cases = [];
      for (const operation of this.operations(phase)) {
        const testcase = makeCase(prng, maxLength, operation);
        cases.push(testcase);
        const raw = target.materializeRaw(testcase);
        if (byteSize(raw) <= maxLength) cases.push(raw);
      }
      return cases;
    },
    validateCase,
    caseFeatures(testcase, target, result) {
      return [
        `op:${testcase.operation}`,
        `${testcase.operation}:mode:${testcase.mode ?? 'lifecycle'}`,
        `${testcase.operation}:message:${lengthBucket(testcase.message.length)}`,
        `${testcase.operation}:secret-zero:${testcase.secretA.every((byte) => byte === 0)}`,
        ...(testcase.mode === 'raw'
          ? [`${testcase.operation}:raw-source:${testcase.matched === true ? 'matched' : 'mutated'}`] : []),
        ...(testcase.mode === 'raw' ? rawFields[testcase.operation].map((field) =>
          `${testcase.operation}:${field}-length:${lengthBucket(testcase[field].length)}`) : []),
        ...(result?.outcome === undefined ? [] : [`${testcase.operation}:outcome:${result.outcome}`]),
        ...(result?.features ?? []),
      ];
    },
    executeCase(target, testcase) { return target.execute(testcase); },
    sampleMask() { return 15; },
    yieldInterval() { return 32; },
  };
}
