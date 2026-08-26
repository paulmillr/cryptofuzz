import {
  argon2Oracle,
  digestOracle,
  hkdfOracle,
  hmacOracle,
  pbkdf2Oracle,
  scryptOracle,
} from './oracle.mjs';

function asBuffer(value) {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function assertEqual(actual, expected, label, testcase) {
  if (expected === undefined) return;
  if (!asBuffer(actual).equals(asBuffer(expected))) {
    const error = new Error(`${label} mismatch for ${testcase.operation}${testcase.digest ? `/${testcase.digest}` : ''}`);
    error.actual = asBuffer(actual).toString('hex');
    error.expected = asBuffer(expected).toString('hex');
    throw error;
  }
}

function targetHmac(target, digest, key, message) {
  return target.hmac({
    operation: 'HMAC',
    digest,
    key,
    message,
    chunks: [message.length],
  }).direct;
}

function manualHkdf(target, testcase) {
  const outputLength = target.hashInfo(testcase.digest, true).outputLen;
  const extracted = targetHmac(target, testcase.digest, testcase.salt, testcase.password);
  const result = new Uint8Array(testcase.keySize);
  let previous = new Uint8Array();
  let offset = 0;
  for (let counter = 1; offset < result.length; counter++) {
    const input = new Uint8Array(previous.length + testcase.info.length + 1);
    input.set(previous);
    input.set(testcase.info, previous.length);
    input[input.length - 1] = counter;
    previous = targetHmac(target, testcase.digest, extracted, input);
    const length = Math.min(outputLength, result.length - offset);
    result.set(previous.subarray(0, length), offset);
    offset += length;
  }
  return result;
}

function manualPbkdf2(target, testcase) {
  const hmacLength = target.hashInfo(testcase.digest, true).outputLen;
  const result = new Uint8Array(testcase.keySize);
  const blockInput = new Uint8Array(testcase.salt.length + 4);
  blockInput.set(testcase.salt);
  let offset = 0;
  for (let block = 1; offset < result.length; block++) {
    new DataView(blockInput.buffer).setUint32(testcase.salt.length, block, false);
    let u = targetHmac(target, testcase.digest, testcase.password, blockInput);
    const accumulator = Uint8Array.from(u);
    for (let iteration = 1; iteration < testcase.iterations; iteration++) {
      u = targetHmac(target, testcase.digest, testcase.password, u);
      for (let index = 0; index < accumulator.length; index++) accumulator[index] ^= u[index];
    }
    const length = Math.min(hmacLength, result.length - offset);
    result.set(accumulator.subarray(0, length), offset);
    offset += length;
  }
  return result;
}

export function executeCase(target, testcase) {
  if (testcase.operation === 'Digest') {
    const { direct, streaming } = target.digest(testcase);
    assertEqual(direct, streaming, 'one-shot/streaming digest', testcase);
    assertEqual(direct, digestOracle(testcase), 'Node digest oracle', testcase);
    return direct;
  }
  if (testcase.operation === 'HMAC') {
    const { direct, streaming } = target.hmac(testcase);
    assertEqual(direct, streaming, 'one-shot/streaming HMAC', testcase);
    assertEqual(direct, hmacOracle(testcase), 'Node HMAC oracle', testcase);
    return direct;
  }
  if (testcase.operation === 'HKDF') {
    const result = target.hkdf(testcase);
    const oracle = hkdfOracle(testcase) ?? manualHkdf(target, testcase);
    assertEqual(result, oracle, 'HKDF oracle', testcase);
    return result;
  }
  if (testcase.operation === 'PBKDF2') {
    const result = target.pbkdf2(testcase);
    const oracle = pbkdf2Oracle(testcase) ?? manualPbkdf2(target, testcase);
    assertEqual(result, oracle, 'PBKDF2 oracle', testcase);
    return result;
  }
  if (testcase.operation === 'Scrypt') {
    const result = target.scrypt(testcase);
    assertEqual(result, scryptOracle(testcase), 'Node scrypt oracle', testcase);
    return result;
  }
  if (testcase.operation === 'Argon2') {
    const result = target.argon2(testcase);
    assertEqual(result, argon2Oracle(testcase), 'Node Argon2 oracle', testcase);
    return result;
  }
  throw new Error(`unknown operation ${testcase.operation}`);
}
