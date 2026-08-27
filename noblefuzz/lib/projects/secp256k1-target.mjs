import { createHash, createHmac } from 'node:crypto';
import * as tinySecp from 'tiny-secp256k1';
import { packageImporter } from '../package-importer.mjs';

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function equalBytes(actual, expected, label, testcase) {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    const error = new Error(`${label} mismatch for ${testcase.operation}`);
    error.actual = Buffer.from(actual).toString('hex');
    error.expected = Buffer.from(expected).toString('hex');
    throw error;
  }
}

function assert(value, label, testcase) {
  if (!value) throw new Error(`${label} failed for ${testcase.operation}`);
}

function attempt(call) {
  try {
    const value = call();
    return value === null || value === undefined ? { ok: false } : { ok: true, value };
  } catch (error) {
    return { ok: false, error };
  }
}

function equalOutcome(actual, expected, label, testcase) {
  if (actual.ok !== expected.ok) throw new Error(`${label} acceptance mismatch for ${testcase.operation}`);
  if (actual.ok) equalBytes(actual.value, expected.value, label, testcase);
}

function bytesToNumber(bytes) {
  const hex = Buffer.from(bytes).toString('hex');
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function numberToBytes(value, length = 32) {
  if (value < 0n || value >= 1n << BigInt(length * 8)) throw new RangeError('integer does not fit');
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex'));
}

function normalizedSecret(bytes) {
  return numberToBytes(bytesToNumber(bytes) % (ORDER - 1n) + 1n);
}

function pointBytes(point) {
  return point.is0() ? null : point.toBytes(true);
}

export async function createStandaloneSecp256k1Target(sourceDirectory) {
  const load = await packageImporter('@noble/secp256k1', sourceDirectory);
  const secp = await load('index.js');
  const sha256 = (message) => Uint8Array.from(createHash('sha256').update(message).digest());
  secp.hashes.sha256 = sha256;
  secp.hashes.hmacSha256 = (key, message) =>
    Uint8Array.from(createHmac('sha256', key).update(message).digest());

  const publicKey = (secret) => secp.getPublicKey(secret, true);
  const strictPoint = (bytes) => secp.Point.fromBytes(bytes).assertValidity();

  function materializeRaw(testcase) {
    const privateKey = normalizedSecret(testcase.secretA);
    const scalar = normalizedSecret(testcase.secretB);
    const publicA = publicKey(privateKey);
    const publicB = publicKey(scalar);
    const raw = { ...testcase, mode: 'raw', matched: true };
    switch (testcase.operation) {
      case 'ECC_PrivateToPublic': return { ...raw, privateKey };
      case 'ECC_ValidatePubkey': return { ...raw, publicKey: publicA };
      case 'ECDH_Derive': return { ...raw, privateKey, publicKey: publicB };
      case 'ECDSA_Sign': return { ...raw, privateKey };
      case 'ECDSA_Verify':
        return { ...raw, publicKey: publicA, signature: secp.sign(testcase.message, privateKey) };
      case 'ECDSA_Recover':
        return { ...raw, signature: secp.sign(testcase.message, privateKey, { format: 'recovered' }) };
      case 'Schnorr_Sign': return { ...raw, privateKey, aux: Uint8Array.from(testcase.aux) };
      case 'Schnorr_Verify':
        return {
          ...raw,
          publicKey: secp.schnorr.getPublicKey(privateKey),
          signature: secp.schnorr.sign(testcase.message, privateKey, testcase.aux),
        };
      case 'ECC_Point_Add':
      case 'ECC_Point_Sub': return { ...raw, pointA: publicA, pointB: publicB };
      case 'ECC_Point_Mul': return { ...raw, pointA: publicA, scalar };
      case 'ECC_Point_Neg':
      case 'ECC_Point_Dbl': return { ...raw, pointA: publicA };
      default: throw new Error(`unsupported secp256k1 operation ${testcase.operation}`);
    }
  }

  function executePoint(testcase) {
    const pointA = attempt(() => strictPoint(testcase.pointA));
    const tinyA = tinySecp.isPoint(testcase.pointA);
    assert(pointA.ok === tinyA, 'tiny-secp256k1 point-A parser oracle', testcase);
    let pointB;
    let tinyB;
    if (testcase.pointB !== undefined) {
      pointB = attempt(() => strictPoint(testcase.pointB));
      tinyB = tinySecp.isPoint(testcase.pointB);
      assert(pointB.ok === tinyB, 'tiny-secp256k1 point-B parser oracle', testcase);
    }
    if (!pointA.ok || (pointB !== undefined && !pointB.ok)) return { outcome: 'reject' };

    let actual;
    let oracle;
    if (testcase.operation === 'ECC_Point_Add') {
      actual = pointBytes(pointA.value.add(pointB.value));
      oracle = tinySecp.pointAdd(testcase.pointA, testcase.pointB, true);
    } else if (testcase.operation === 'ECC_Point_Sub') {
      actual = pointBytes(pointA.value.subtract(pointB.value));
      const negative = tinySecp.pointMultiply(testcase.pointB, numberToBytes(ORDER - 1n), true);
      oracle = tinySecp.pointAdd(testcase.pointA, negative, true);
    } else if (testcase.operation === 'ECC_Point_Mul') {
      const scalar = bytesToNumber(testcase.scalar);
      const scalarBytes = attempt(() => scalar > 0n && scalar < ORDER ? numberToBytes(scalar) : undefined);
      const noble = attempt(() => pointBytes(pointA.value.multiply(scalar)));
      const tiny = scalarBytes.ok ? attempt(() => tinySecp.pointMultiply(testcase.pointA, scalarBytes.value, true)) : { ok: false };
      if (noble.ok !== tiny.ok) throw new Error(`tiny-secp256k1 scalar acceptance mismatch for ${testcase.operation}`);
      if (!noble.ok) return { outcome: 'reject' };
      actual = noble.value;
      oracle = tiny.value;
    } else if (testcase.operation === 'ECC_Point_Neg') {
      actual = pointBytes(pointA.value.negate());
      oracle = tinySecp.pointMultiply(testcase.pointA, numberToBytes(ORDER - 1n), true);
    } else if (testcase.operation === 'ECC_Point_Dbl') {
      actual = pointBytes(pointA.value.double());
      oracle = tinySecp.pointAdd(testcase.pointA, testcase.pointA, true);
    }
    if (actual === null || oracle === null) {
      assert(actual === null && oracle === null, 'tiny-secp256k1 identity oracle', testcase);
      return { outcome: 'accept', value: Uint8Array.of(0) };
    }
    equalBytes(actual, oracle, 'tiny-secp256k1 point oracle', testcase);
    return { outcome: 'accept', value: actual };
  }

  function executeRaw(testcase) {
    if (testcase.operation === 'ECC_PrivateToPublic') {
      const actual = attempt(() => publicKey(testcase.privateKey));
      const oracle = attempt(() => tinySecp.pointFromScalar(testcase.privateKey, true));
      equalOutcome(actual, oracle, 'tiny-secp256k1 public-key oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'ECC_ValidatePubkey') {
      const actual = secp.utils.isValidPublicKey(testcase.publicKey);
      const oracle = tinySecp.isPoint(testcase.publicKey);
      assert(actual === oracle, 'tiny-secp256k1 public-key validation oracle', testcase);
      return { outcome: actual ? 'accept' : 'reject', value: actual };
    }
    if (testcase.operation === 'ECDH_Derive') {
      const actual = attempt(() => secp.getSharedSecret(testcase.privateKey, testcase.publicKey, true));
      const oracle = attempt(() => tinySecp.pointMultiply(testcase.publicKey, testcase.privateKey, true));
      equalOutcome(actual, oracle, 'tiny-secp256k1 ECDH oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'ECDSA_Sign') {
      const actual = attempt(() => secp.sign(testcase.message, testcase.privateKey));
      const oracle = attempt(() => tinySecp.sign(sha256(testcase.message), testcase.privateKey));
      equalOutcome(actual, oracle, 'tiny-secp256k1 ECDSA oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'ECDSA_Verify') {
      let actual = false;
      let oracle = false;
      try { actual = secp.verify(testcase.signature, testcase.message, testcase.publicKey); } catch (_) {}
      try { oracle = tinySecp.verify(sha256(testcase.message), testcase.publicKey, testcase.signature, true); } catch (_) {}
      assert(actual === oracle, 'tiny-secp256k1 ECDSA verification oracle', testcase);
      return { outcome: actual ? 'accept' : 'reject', value: actual };
    }
    if (testcase.operation === 'ECDSA_Recover') {
      const actual = attempt(() => secp.recoverPublicKey(testcase.signature, testcase.message));
      const oracle = attempt(() => {
        if (testcase.signature.length !== 65) throw new RangeError('invalid recovered signature');
        return tinySecp.recover(
          sha256(testcase.message), testcase.signature.subarray(1), testcase.signature[0], true,
        );
      });
      equalOutcome(actual, oracle, 'tiny-secp256k1 recovery oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'Schnorr_Sign') {
      const actual = attempt(() => secp.schnorr.sign(testcase.message, testcase.privateKey, testcase.aux));
      const oracle = attempt(() => tinySecp.signSchnorr(testcase.message, testcase.privateKey, testcase.aux));
      equalOutcome(actual, oracle, 'tiny-secp256k1 Schnorr oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'Schnorr_Verify') {
      let actual = false;
      let oracle = false;
      try { actual = secp.schnorr.verify(testcase.signature, testcase.message, testcase.publicKey); } catch (_) {}
      try { oracle = tinySecp.verifySchnorr(testcase.message, testcase.publicKey, testcase.signature); } catch (_) {}
      // The standalone package deliberately rejects zero r/s values more strictly
      // than BIP340/libsecp256k1. Do not turn that documented policy edge into a
      // differential failure if a crafted valid signature reaches it.
      const hasPolicyZero = testcase.signature.length === 64 &&
        (testcase.signature.subarray(0, 32).every((byte) => byte === 0) ||
          testcase.signature.subarray(32).every((byte) => byte === 0));
      assert(actual === oracle || (!actual && oracle && hasPolicyZero),
        'tiny-secp256k1 Schnorr verification oracle', testcase);
      return { outcome: actual ? 'accept' : 'reject', value: actual };
    }
    return executePoint(testcase);
  }

  const knownSecret = numberToBytes(1n);
  equalBytes(publicKey(knownSecret), tinySecp.pointFromScalar(knownSecret, true),
    'tiny-secp256k1 startup oracle', { operation: 'ECC_PrivateToPublic' });

  return {
    materializeRaw,
    execute(testcase) {
      return executeRaw(testcase.mode === 'raw' ? testcase : materializeRaw(testcase));
    },
  };
}
