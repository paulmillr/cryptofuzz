import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import { packageImporter } from '../package-importer.mjs';

const ORDER = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

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

function bytesToNumberLE(bytes) {
  const hex = Buffer.from(bytes).reverse().toString('hex');
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function numberToBytesLE(value) {
  if (value < 0n || value >= 1n << 256n) throw new RangeError('integer does not fit');
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex').reverse());
}

function normalizedScalar(bytes) {
  return bytesToNumberLE(bytes) % (ORDER - 1n) + 1n;
}

function nodePrivateKey(secretKey) {
  if (secretKey.length !== 32) throw new RangeError('Ed25519 secret key must contain 32 bytes');
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, secretKey]), format: 'der', type: 'pkcs8' });
}

function nodePublicKey(publicKey) {
  if (publicKey.length !== 32) throw new RangeError('Ed25519 public key must contain 32 bytes');
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, publicKey]), format: 'der', type: 'spki' });
}

function nodePublicFromSecret(secretKey) {
  return Uint8Array.from(createPublicKey(nodePrivateKey(secretKey)).export({ format: 'der', type: 'spki' }).subarray(-32));
}

function requireSodiumWasm() {
  const wasmExport = sodium.libsodium?._crypto_core_ed25519_add;
  if (typeof wasmExport !== 'function' || !Function.prototype.toString.call(wasmExport).includes('[native code]')) {
    throw new Error('libsodium WebAssembly backend is unavailable');
  }
}

export async function createStandaloneEd25519Target(sourceDirectory) {
  await sodium.ready;
  requireSodiumWasm();
  const load = await packageImporter('@noble/ed25519', sourceDirectory);
  const ed = await load('index.js');
  ed.hashes.sha512 = (message) => Uint8Array.from(createHash('sha512').update(message).digest());

  const strictPoint = (bytes) => {
    const point = ed.Point.fromBytes(bytes, false).assertValidity();
    if (!point.isTorsionFree() || point.isSmallOrder()) throw new RangeError('point is not in the prime-order subgroup');
    return point;
  };

  function materializeRaw(testcase) {
    const privateKey = Uint8Array.from(testcase.secretA);
    const publicKey = ed.getPublicKey(privateKey);
    const scalarA = normalizedScalar(testcase.secretA);
    const scalarB = normalizedScalar(testcase.secretB);
    const pointA = ed.Point.BASE.multiply(scalarA).toBytes();
    const pointB = ed.Point.BASE.multiply(scalarB).toBytes();
    const raw = { ...testcase, mode: 'raw', matched: true };
    switch (testcase.operation) {
      case 'ECC_PrivateToPublic': return { ...raw, privateKey };
      case 'ECC_ValidatePubkey': return { ...raw, publicKey };
      case 'ECDSA_Sign': return { ...raw, privateKey };
      case 'ECDSA_Verify': return { ...raw, publicKey, signature: ed.sign(testcase.message, privateKey) };
      case 'ECC_Point_Add':
      case 'ECC_Point_Sub': return { ...raw, pointA, pointB };
      case 'ECC_Point_Mul': return { ...raw, pointA, scalar: numberToBytesLE(scalarB) };
      case 'ECC_Point_Neg':
      case 'ECC_Point_Dbl': return { ...raw, pointA };
      default: throw new Error(`unsupported Ed25519 operation ${testcase.operation}`);
    }
  }

  function executePoint(testcase) {
    const pointA = attempt(() => strictPoint(testcase.pointA));
    const sodiumA = testcase.pointA.length === 32 && sodium.crypto_core_ed25519_is_valid_point(testcase.pointA);
    assert(pointA.ok === sodiumA, 'libsodium point-A parser oracle', testcase);
    let pointB;
    let sodiumB;
    if (testcase.pointB !== undefined) {
      pointB = attempt(() => strictPoint(testcase.pointB));
      sodiumB = testcase.pointB.length === 32 && sodium.crypto_core_ed25519_is_valid_point(testcase.pointB);
      assert(pointB.ok === sodiumB, 'libsodium point-B parser oracle', testcase);
    }
    if (!pointA.ok || (pointB !== undefined && !pointB.ok)) return { outcome: 'reject' };

    let actual;
    let oracle;
    if (testcase.operation === 'ECC_Point_Add') {
      actual = pointA.value.add(pointB.value).toBytes();
      oracle = sodium.crypto_core_ed25519_add(testcase.pointA, testcase.pointB);
    } else if (testcase.operation === 'ECC_Point_Sub') {
      actual = pointA.value.subtract(pointB.value).toBytes();
      oracle = sodium.crypto_core_ed25519_sub(testcase.pointA, testcase.pointB);
    } else if (testcase.operation === 'ECC_Point_Mul') {
      const scalar = bytesToNumberLE(testcase.scalar);
      const scalarBytes = attempt(() => scalar > 0n && scalar < ORDER ? numberToBytesLE(scalar) : undefined);
      const noble = attempt(() => pointA.value.multiply(scalar).toBytes());
      const sodiumResult = scalarBytes.ok
        ? attempt(() => sodium.crypto_scalarmult_ed25519_noclamp(scalarBytes.value, testcase.pointA)) : { ok: false };
      equalOutcome(noble, sodiumResult, 'libsodium scalar multiplication oracle', testcase);
      return { outcome: noble.ok ? 'accept' : 'reject', value: noble.value };
    } else if (testcase.operation === 'ECC_Point_Neg') {
      actual = pointA.value.negate().toBytes();
      oracle = sodium.crypto_core_ed25519_sub(ed.Point.ZERO.toBytes(), testcase.pointA);
    } else if (testcase.operation === 'ECC_Point_Dbl') {
      actual = pointA.value.double().toBytes();
      oracle = sodium.crypto_core_ed25519_add(testcase.pointA, testcase.pointA);
    }
    equalBytes(actual, oracle, 'libsodium Ed25519 point oracle', testcase);
    return { outcome: 'accept', value: actual };
  }

  function executeRaw(testcase) {
    if (testcase.operation === 'ECC_PrivateToPublic') {
      const actual = attempt(() => ed.getPublicKey(testcase.privateKey));
      const node = attempt(() => nodePublicFromSecret(testcase.privateKey));
      const libsodium = attempt(() => sodium.crypto_sign_seed_keypair(testcase.privateKey).publicKey);
      equalOutcome(actual, node, 'Node/OpenSSL Ed25519 public-key oracle', testcase);
      equalOutcome(actual, libsodium, 'libsodium Ed25519 public-key oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'ECC_ValidatePubkey') {
      const actual = attempt(() => strictPoint(testcase.publicKey)).ok;
      const oracle = testcase.publicKey.length === 32 && sodium.crypto_core_ed25519_is_valid_point(testcase.publicKey);
      assert(actual === oracle, 'libsodium Ed25519 validation oracle', testcase);
      return { outcome: actual ? 'accept' : 'reject', value: actual };
    }
    if (testcase.operation === 'ECDSA_Sign') {
      const actual = attempt(() => ed.sign(testcase.message, testcase.privateKey));
      const node = attempt(() => nodeSign(null, testcase.message, nodePrivateKey(testcase.privateKey)));
      const libsodium = attempt(() => sodium.crypto_sign_detached(testcase.message,
        sodium.crypto_sign_seed_keypair(testcase.privateKey).privateKey));
      equalOutcome(actual, node, 'Node/OpenSSL Ed25519 signature oracle', testcase);
      equalOutcome(actual, libsodium, 'libsodium Ed25519 signature oracle', testcase);
      return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
    }
    if (testcase.operation === 'ECDSA_Verify') {
      let zip215 = false;
      let strict = false;
      let libsodium = false;
      let node = false;
      try { zip215 = ed.verify(testcase.signature, testcase.message, testcase.publicKey); } catch (_) {}
      try { strict = ed.verify(testcase.signature, testcase.message, testcase.publicKey, { zip215: false }); } catch (_) {}
      try { libsodium = sodium.crypto_sign_verify_detached(testcase.signature, testcase.message, testcase.publicKey); } catch (_) {}
      try { node = nodeVerify(null, testcase.message, nodePublicKey(testcase.publicKey), testcase.signature); } catch (_) {}
      assert(strict === libsodium, 'libsodium Ed25519 verification oracle', testcase);
      if (testcase.matched === true) assert(strict === node, 'Node/OpenSSL Ed25519 verification oracle', testcase);
      assert(!strict || zip215, 'ZIP-215 verification superset', testcase);
      return {
        outcome: zip215 ? 'accept' : 'reject',
        value: zip215,
        features: [`${testcase.operation}:strict:${strict}`, `${testcase.operation}:zip215:${zip215}`],
      };
    }
    return executePoint(testcase);
  }

  const knownSecret = new Uint8Array(32).fill(7);
  equalBytes(ed.getPublicKey(knownSecret), nodePublicFromSecret(knownSecret),
    'Node/OpenSSL Ed25519 startup oracle', { operation: 'ECC_PrivateToPublic' });

  return {
    materializeRaw,
    execute(testcase) {
      return executeRaw(testcase.mode === 'raw' ? testcase : materializeRaw(testcase));
    },
  };
}
