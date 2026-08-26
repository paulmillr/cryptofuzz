import { createCurvesTarget } from './curves-target.mjs';
import { byteSize, cloneCase, compatibleDonor, mutateBytes } from '../mutation.mjs';

export const CURVE_FAST_OPERATIONS = Object.freeze([
  'ECC_PrivateToPublic', 'ECC_ValidatePubkey', 'ECDH_Derive', 'ECDSA_Sign', 'ECDSA_Verify', 'ECDSA_Recover',
  'Schnorr_Sign', 'Schnorr_Verify', 'ECC_Point_Add', 'ECC_Point_Sub', 'ECC_Point_Cmp', 'ECC_Point_Mul',
  'ECC_Point_Neg', 'ECC_Point_Dbl', 'BLS_PrivateToPublic', 'BLS_PrivateToPublic_G2', 'BLS_HashToG1',
  'BLS_HashToG2', 'BLS_MapToG1', 'BLS_MapToG2', 'BLS_Sign', 'BLS_Verify', 'BLS_Compress_G1',
  'BLS_Decompress_G1', 'BLS_Compress_G2', 'BLS_Decompress_G2', 'BLS_IsG1OnCurve', 'BLS_IsG2OnCurve',
  'BLS_G1_Add', 'BLS_G1_Mul', 'BLS_G1_Neg', 'BLS_G1_IsEq', 'BLS_G2_Add', 'BLS_G2_Mul', 'BLS_G2_Neg',
  'BLS_G2_IsEq', 'BLS_Aggregate_G1', 'BLS_Aggregate_G2', 'BLS_G1_MultiExp',
  'BignumCalc_Mod_BLS12_381_P', 'BignumCalc_Mod_BLS12_381_R',
]);
export const CURVE_PAIRING_OPERATIONS = Object.freeze(['BLS_Pairing', 'BLS_FinalExp']);

const WEIERSTRASS = [
  'secp256k1', 'secp256r1', 'secp384r1', 'secp521r1',
  'brainpool256r1', 'brainpool384r1', 'brainpool512r1',
];
const EDWARDS = ['ed25519', 'ed448'];
const MONTGOMERY = ['x25519', 'x448'];
const PAIRING = ['BLS12_381', 'alt_bn128'];
const BLS_ONLY = new Set(['BLS_HashToG1', 'BLS_HashToG2', 'BLS_MapToG1', 'BLS_MapToG2', 'BLS_Sign', 'BLS_Verify',
  'BLS_Compress_G1', 'BLS_Decompress_G1', 'BLS_Compress_G2', 'BLS_Decompress_G2',
  'BLS_Aggregate_G1', 'BLS_Aggregate_G2']);
const RAW_FIELDS = Object.freeze({
  ECC_PrivateToPublic: ['privateKey'],
  ECC_ValidatePubkey: ['publicKey'],
  ECDH_Derive: ['secretKey', 'publicKey'],
  ECDSA_Sign: ['privateKey'],
  ECDSA_Verify: ['publicKey', 'signature'],
  ECDSA_Recover: ['signature'],
  Schnorr_Sign: ['privateKey', 'aux'],
  Schnorr_Verify: ['publicKey', 'signature'],
  ECC_Point_Add: ['pointA', 'pointB'],
  ECC_Point_Sub: ['pointA', 'pointB'],
  ECC_Point_Cmp: ['pointA', 'pointB'],
  ECC_Point_Mul: ['pointA', 'scalar'],
  ECC_Point_Neg: ['pointA'],
  ECC_Point_Dbl: ['pointA'],
  BLS_PrivateToPublic: ['privateKey'],
  BLS_PrivateToPublic_G2: ['privateKey'],
  BLS_Verify: ['publicKey', 'signature'],
  BLS_Decompress_G1: ['point'],
  BLS_Decompress_G2: ['point'],
  BLS_IsG1OnCurve: ['point'],
  BLS_IsG2OnCurve: ['point'],
  BLS_G1_Add: ['pointA', 'pointB'],
  BLS_G1_Mul: ['pointA', 'scalar'],
  BLS_G1_Neg: ['pointA'],
  BLS_G1_IsEq: ['pointA', 'pointB'],
  BLS_G2_Add: ['pointA', 'pointB'],
  BLS_G2_Mul: ['pointA', 'scalar'],
  BLS_G2_Neg: ['pointA'],
  BLS_G2_IsEq: ['pointA', 'pointB'],
  BLS_Aggregate_G1: ['pointA', 'pointB'],
  BLS_Aggregate_G2: ['pointA', 'pointB'],
  BLS_G1_MultiExp: ['pointA', 'pointB', 'scalar'],
});

function curvesFor(operation) {
  if (operation.startsWith('Schnorr_')) return ['secp256k1'];
  if (operation === 'ECDH_Derive') return [...WEIERSTRASS, ...MONTGOMERY];
  if (operation === 'ECDSA_Recover') return WEIERSTRASS;
  if (operation === 'ECDSA_Sign' || operation === 'ECDSA_Verify') return [...WEIERSTRASS, ...EDWARDS];
  if (operation.startsWith('ECC_Point_') || operation === 'ECC_ValidatePubkey') return [...WEIERSTRASS, ...EDWARDS];
  if (operation === 'ECC_PrivateToPublic') return [...WEIERSTRASS, ...EDWARDS, ...MONTGOMERY];
  if (operation.startsWith('BignumCalc_')) return ['BLS12_381'];
  if (BLS_ONLY.has(operation) || operation === 'BLS_PrivateToPublic') return ['BLS12_381'];
  if (operation.startsWith('BLS_')) return PAIRING;
  throw new Error(`no curve set for ${operation}`);
}

function descriptor(target, name) {
  if (name === 'BLS12_381' || name === 'alt_bn128') return { name, secretLength: 32 };
  return target.descriptors.find((item) => item.name === name);
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

function makeCase(prng, target, maxLength, operation, forcedCurve) {
  const curve = forcedCurve ?? prng.pick(curvesFor(operation));
  const info = descriptor(target, curve);
  const fixed = 2 * info.secretLength;
  const messageLength = Math.min(maxLength - fixed, prng.pick([0, 1, 16, 32, 64, 128, 255].filter((n) => n <= maxLength - fixed)));
  return {
    version: 1,
    operation,
    curve,
    secretA: patternedBytes(prng, info.secretLength),
    secretB: patternedBytes(prng, info.secretLength),
    message: operation.startsWith('Schnorr_') ? patternedBytes(prng, 32) : patternedBytes(prng, messageLength),
    dst: Uint8Array.from(Buffer.from('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_')),
  };
}

export function validateCurveCase(testcase, maxLength = 4096, phase) {
  const operations = phase === 'pairing' ? CURVE_PAIRING_OPERATIONS : CURVE_FAST_OPERATIONS;
  if (testcase?.version !== 1 || !operations.includes(testcase.operation)) throw new Error('invalid curve testcase envelope');
  if (!curvesFor(testcase.operation).includes(testcase.curve)) throw new Error('operation does not support selected curve');
  for (const field of ['secretA', 'secretB', 'message', 'dst']) {
    if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes`);
  }
  if (testcase.mode !== undefined && testcase.mode !== 'raw') throw new Error('invalid curve testcase mode');
  if (testcase.mode === 'raw') {
    const rawFields = RAW_FIELDS[testcase.operation];
    if (rawFields === undefined) throw new Error(`${testcase.operation} has no raw-input mode`);
    for (const field of rawFields) {
      if (!(testcase[field] instanceof Uint8Array)) throw new Error(`${field} must be bytes in raw-input mode`);
    }
    if (testcase.matched !== undefined && typeof testcase.matched !== 'boolean') throw new Error('matched must be boolean');
  }
  if (testcase.secretA.length !== testcase.secretB.length) throw new Error('curve secret lengths differ');
  if (testcase.secretA.length < 28 || testcase.secretA.length > 66) throw new Error('invalid curve secret length');
  if (testcase.operation.startsWith('Schnorr_') && testcase.message.length !== 32) throw new Error('Schnorr message must be 32 bytes');
  if (testcase.dst.length > 255) throw new Error('BLS DST exceeds limit');
  if (byteSize(testcase) > maxLength) throw new Error('testcase exceeds max length');
  return testcase;
}

export const curvesProject = {
  name: 'noble-curves',
  packageName: '@noble/curves',
  phases: ['fast', 'pairing'],
  createTarget: createCurvesTarget,
  operations(phase) { return phase === 'pairing' ? CURVE_PAIRING_OPERATIONS : CURVE_FAST_OPERATIONS; },
  chooseOperation(phase, prng) { return prng.pick(this.operations(phase)); },
  generateCase(phase, prng, target, maxLength, operation) {
    const testcase = makeCase(prng, target, maxLength, operation);
    if (RAW_FIELDS[operation] !== undefined && prng.bool()) {
      const raw = target.materializeRaw(testcase);
      if (byteSize(raw) <= maxLength) return raw;
    }
    return testcase;
  },
  mutateCase(base, phase, prng, target, maxLength, corpus) {
    if (prng.bool(1, 5)) return makeCase(prng, target, maxLength, prng.pick(this.operations(phase)));
    let testcase = cloneCase(base);
    if (testcase.mode !== 'raw' && RAW_FIELDS[testcase.operation] !== undefined && prng.bool(1, 3)) {
      const raw = target.materializeRaw(testcase);
      if (byteSize(raw) <= maxLength) testcase = raw;
    }
    if (testcase.mode === 'raw') {
      const fields = [...RAW_FIELDS[testcase.operation], 'message', 'dst'];
      const field = prng.pick(fields);
      const donor = compatibleDonor(corpus, testcase, fields, prng,
        (candidate, current) => candidate.mode === 'raw' && candidate.curve === current.curve);
      const maximum = maxLength - byteSize(testcase) + testcase[field].length;
      testcase[field] = mutateBytes(testcase[field], prng, maximum, donor?.[field]);
      testcase.matched = false;
      if (testcase.operation.startsWith('Schnorr_') && testcase.message.length !== 32) {
        testcase.message = mutateBytes(testcase.message, prng, 32).subarray(0, 32);
        if (testcase.message.length !== 32) testcase.message = prng.bytes(32);
      }
      if (testcase.dst.length > 255) testcase.dst = testcase.dst.subarray(0, 255);
      validateCurveCase(testcase, maxLength, phase);
      return testcase;
    }
    const field = prng.pick(['secretA', 'secretB', 'message']);
    if (testcase[field].length > 0) testcase[field][prng.int(testcase[field].length)] ^= 1 << prng.int(8);
    validateCurveCase(testcase, maxLength, phase);
    return testcase;
  },
  seedCases(phase, prng, target, maxLength) {
    const cases = [];
    for (const operation of this.operations(phase)) {
      for (const curve of curvesFor(operation)) {
        const testcase = makeCase(prng, target, maxLength, operation, curve);
        cases.push(testcase);
        if (RAW_FIELDS[operation] !== undefined) {
          let raw;
          try {
            raw = target.materializeRaw(testcase);
          } catch (error) {
            error.message = `could not materialize ${operation}/${curve} (secretA=${Buffer.from(testcase.secretA).toString('hex')}): ${error.message}`;
            throw error;
          }
          if (byteSize(raw) <= maxLength) cases.push(raw);
        }
      }
    }
    return cases;
  },
  validateCase: validateCurveCase,
  caseFeatures(testcase, target, result) {
    return [`op:${testcase.operation}`, `curve:${testcase.curve}`, `curve-op:${testcase.operation}:${testcase.curve}`,
      `${testcase.operation}:message:${testcase.mode === 'raw' ? lengthBucket(testcase.message.length) : testcase.message.length}`,
      `${testcase.operation}:secret-zero:${testcase.secretA.every((b) => b === 0)}`,
      `${testcase.operation}:mode:${testcase.mode ?? 'lifecycle'}`,
      ...(testcase.mode === 'raw' ? [`${testcase.operation}:raw-source:${testcase.matched === true ? 'matched' : 'mutated'}`] : []),
      ...(testcase.mode === 'raw' ? RAW_FIELDS[testcase.operation].map((field) =>
        `${testcase.operation}:${field}-length:${lengthBucket(testcase[field].length)}`) : []),
      ...(result?.outcome === undefined ? [] : [`${testcase.operation}:raw-outcome:${result.outcome}`])];
  },
  executeCase(target, testcase) { return target.execute(testcase); },
  sampleMask(phase) { return phase === 'pairing' ? 0 : 15; },
  yieldInterval(phase) { return phase === 'pairing' ? 1 : 32; },
};
