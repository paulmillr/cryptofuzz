import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  getCurves,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import mcl from 'mcl-wasm';
import * as tinySecp from 'tiny-secp256k1';
import { buildBn128 } from 'ffjavascript';
import { packageImporter } from '../package-importer.mjs';

const NODE_CURVES = new Set(getCurves());
export const FIELD_CALC_OPERATIONS = Object.freeze([
  'Add', 'Sub', 'Mul', 'Div', 'Sqr', 'InvMod', 'Sqrt', 'Neg', 'IsEq', 'IsZero',
]);

function equalBytes(actual, expected, label, testcase) {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    const error = new Error(`${label} mismatch for ${testcase.operation}/${testcase.curve}`);
    error.actual = Buffer.from(actual).toString('hex');
    error.expected = Buffer.from(expected).toString('hex');
    throw error;
  }
}

function assert(value, label, testcase) {
  if (!value) throw new Error(`${label} failed for ${testcase.operation}/${testcase.curve}`);
}

function attempt(call) {
  try {
    return { accepted: true, value: call() };
  } catch (error) {
    return { accepted: false, error };
  }
}

function rawOutcome(accepted, value) {
  return { outcome: accepted ? 'accept' : 'reject', value };
}

function bytesToNumber(bytes) {
  const hex = Buffer.from(bytes).toString('hex');
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function numberToBytes(value, length) {
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex'));
}

function bytesIndex(bytes, limit) {
  let value = 0;
  for (let index = 0; index < Math.min(bytes.length, 4); index++) value = (value * 256 + bytes[index]) >>> 0;
  return value % limit;
}

function b64(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function normalizedScalar(curve, bytes) {
  const order = curve.Point.Fn.ORDER;
  return bytesToNumber(bytes) % (order - 1n) + 1n;
}

function normalizedSecret(info, bytes) {
  if (info.kind !== 'weierstrass') return bytes;
  return numberToBytes(normalizedScalar(info.curve, bytes), info.curve.lengths.secretKey);
}

function nodePublicAndSecret(info, secret, publicKey) {
  if (!info.nodeName || !NODE_CURVES.has(info.nodeName)) return;
  const ecdh = createECDH(info.nodeName);
  ecdh.setPrivateKey(secret);
  const nodePublic = ecdh.getPublicKey(undefined, 'compressed');
  equalBytes(nodePublic, publicKey, 'Node/OpenSSL public key oracle', { operation: 'ECC_PrivateToPublic', curve: info.name });
  return ecdh;
}

function nodeKeyPair(info, secret, publicKey) {
  if (info.jwkCurve === undefined) return;
  let jwk;
  if (info.kind === 'weierstrass') {
    const affine = info.curve.Point.fromBytes(publicKey).toAffine();
    const length = info.curve.Point.Fp.BYTES;
    jwk = {
      kty: 'EC',
      crv: info.jwkCurve,
      x: b64(numberToBytes(affine.x, length)),
      y: b64(numberToBytes(affine.y, length)),
      d: b64(secret),
    };
  } else {
    jwk = { kty: 'OKP', crv: info.jwkCurve, x: b64(publicKey), d: b64(secret) };
  }
  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function mclPoint(kind, point) {
  const result = new mcl[kind]();
  result.deserialize(point.toBytes(true));
  return result;
}

function mclScalar(value) {
  const result = new mcl.Fr();
  result.setStr(value.toString());
  return result;
}

function mclGroupOracle(testcase, result, P, P2, Q, Q2, a, b) {
  if (testcase.curve !== 'BLS12_381') return;
  const resultBytes = result.is0() ? undefined : result.toBytes(true);
  const kind = resultBytes?.length === 96 || ['BLS_PrivateToPublic_G2', 'BLS_IsG2OnCurve',
    'BLS_G2_Add', 'BLS_G2_Mul', 'BLS_G2_Neg', 'BLS_G2_IsEq', 'BLS_Aggregate_G2',
    'BLS_HashToG2', 'BLS_MapToG2', 'BLS_Sign', 'BLS_Verify', 'BLS_Compress_G2',
    'BLS_Decompress_G2'].includes(testcase.operation) ? 'G2' : 'G1';
  const mP = mclPoint('G1', P);
  const mP2 = mclPoint('G1', P2);
  const mQ = mclPoint('G2', Q);
  const mQ2 = mclPoint('G2', Q2);
  let oracle;
  switch (testcase.operation) {
    case 'BLS_PrivateToPublic':
    case 'BLS_IsG1OnCurve':
    case 'BLS_G1_IsEq':
    case 'BLS_Compress_G1':
    case 'BLS_Decompress_G1': oracle = mP; break;
    case 'BLS_PrivateToPublic_G2':
    case 'BLS_IsG2OnCurve':
    case 'BLS_G2_IsEq':
    case 'BLS_Compress_G2':
    case 'BLS_Decompress_G2': oracle = mQ; break;
    case 'BLS_G1_Add':
    case 'BLS_Aggregate_G1': oracle = mcl.add(mP, mP2); break;
    case 'BLS_G1_Mul': oracle = mcl.mul(mP, mclScalar(b)); break;
    case 'BLS_G1_Neg': oracle = mcl.neg(mP); break;
    case 'BLS_G2_Add':
    case 'BLS_Aggregate_G2': oracle = mcl.add(mQ, mQ2); break;
    case 'BLS_G2_Mul': oracle = mcl.mul(mQ, mclScalar(b)); break;
    case 'BLS_G2_Neg': oracle = mcl.neg(mQ); break;
    case 'BLS_G1_MultiExp':
      oracle = mcl.add(mcl.mul(mP, mclScalar(b)), mcl.mul(mP2, mclScalar(a)));
      break;
    default:
      // Hash/map/sign outputs use different API-level DST conventions in mcl,
      // but successful deserialization still independently validates subgroup
      // membership and standardized point encoding.
      if (resultBytes !== undefined) oracle = mclPoint(kind, result);
  }
  if (oracle === undefined) return;
  if (result.is0()) {
    assert(oracle.isZero(), `mcl-wasm ${kind} identity oracle`, testcase);
  } else {
    equalBytes(resultBytes, oracle.serialize(), `mcl-wasm ${kind} oracle`, testcase);
  }
}

function mclPairingBytes(g1, g2) {
  const raw = mcl.pairing(mclPoint('G1', g1), mclPoint('G2', g2)).serialize();
  const result = new Uint8Array(raw.length);
  for (let index = 0; index < 12; index += 2) {
    result.set(raw.subarray((index + 1) * 48, (index + 2) * 48), index * 48);
    result.set(raw.subarray(index * 48, (index + 1) * 48), (index + 1) * 48);
  }
  return result;
}

function ffScalar(curve, value) {
  return curve.Fr.e(value);
}

function ffPoint(curve, kind, scalar) {
  const group = curve[kind];
  return group.timesFr(group.g, ffScalar(curve, scalar));
}

function ffPointValues(curve, kind, point) {
  return curve[kind].toObject(curve[kind].toAffine(point));
}

function noblePointValues(point) {
  const affine = point.toAffine();
  if (typeof affine.x === 'bigint') return [affine.x, affine.y, 1n];
  return [[affine.x.c0, affine.x.c1], [affine.y.c0, affine.y.c1], [1n, 0n]];
}

function equalNestedBigints(actual, expected, label, testcase) {
  const actualFlat = actual.flat(Infinity);
  const expectedFlat = expected.flat(Infinity);
  if (actualFlat.length !== expectedFlat.length || actualFlat.some((value, index) => value !== expectedFlat[index])) {
    const error = new Error(`${label} mismatch for ${testcase.operation}/${testcase.curve}`);
    error.actual = actualFlat.map(String).join(',');
    error.expected = expectedFlat.map(String).join(',');
    throw error;
  }
}

function ffPairingOracle(info, noble, testcase) {
  const [a, b] = blsScalars(info.curve, testcase);
  const ffResult = info.wasm.pairing(ffPoint(info.wasm, 'G1', a), ffPoint(info.wasm, 'G2', b));
  const n = noble;
  const nobleValues = [
    [[n.c0.c0.c0, n.c0.c0.c1], [n.c0.c1.c0, n.c0.c1.c1], [n.c0.c2.c0, n.c0.c2.c1]],
    [[n.c1.c0.c0, n.c1.c0.c1], [n.c1.c1.c0, n.c1.c1.c1], [n.c1.c2.c0, n.c1.c2.c1]],
  ];
  equalNestedBigints(nobleValues, info.wasm.Gt.toObject(ffResult), 'ffjavascript BN254 WASM pairing oracle', testcase);
}

function ffGroupOracle(info, testcase, result, P, P2, Q, Q2, a, b) {
  if (testcase.curve !== 'alt_bn128') return;
  const ff = info.wasm;
  const scalar = (value) => ffScalar(ff, value);
  const fP = ffPoint(ff, 'G1', a);
  const fP2 = ffPoint(ff, 'G1', b);
  const fQ = ffPoint(ff, 'G2', a);
  const fQ2 = ffPoint(ff, 'G2', b);
  let kind;
  let oracle;
  switch (testcase.operation) {
    case 'BLS_PrivateToPublic_G2':
    case 'BLS_IsG2OnCurve':
    case 'BLS_G2_IsEq': kind = 'G2'; oracle = fQ; break;
    case 'BLS_IsG1OnCurve':
    case 'BLS_G1_IsEq': kind = 'G1'; oracle = fP; break;
    case 'BLS_G1_Add': kind = 'G1'; oracle = ff.G1.add(fP, fP2); break;
    case 'BLS_G1_Mul': kind = 'G1'; oracle = ff.G1.timesFr(fP, scalar(b)); break;
    case 'BLS_G1_Neg': kind = 'G1'; oracle = ff.G1.neg(fP); break;
    case 'BLS_G2_Add': kind = 'G2'; oracle = ff.G2.add(fQ, fQ2); break;
    case 'BLS_G2_Mul': kind = 'G2'; oracle = ff.G2.timesFr(fQ, scalar(b)); break;
    case 'BLS_G2_Neg': kind = 'G2'; oracle = ff.G2.neg(fQ); break;
    case 'BLS_G1_MultiExp':
      kind = 'G1';
      oracle = ff.G1.add(ff.G1.timesFr(fP, scalar(b)), ff.G1.timesFr(fP2, scalar(a)));
      break;
    default: return;
  }
  if (result.is0()) {
    assert(ff[kind].isZero(oracle), `ffjavascript BN254 WASM ${kind} identity oracle`, testcase);
    return;
  }
  equalNestedBigints(noblePointValues(result), ffPointValues(ff, kind, oracle),
    `ffjavascript BN254 WASM ${kind} oracle`, testcase);
}

function pointOperation(info, testcase) {
  const curve = info.curve;
  const a = normalizedScalar(curve, testcase.secretA);
  const b = normalizedScalar(curve, testcase.secretB);
  const P = curve.Point.BASE.multiply(a);
  const Q = curve.Point.BASE.multiply(b);
  let result;
  if (testcase.operation === 'ECC_Point_Add') {
    result = P.add(Q);
    assert(result.equals(curve.Point.BASE.multiply((a + b) % curve.Point.Fn.ORDER)), 'point addition identity', testcase);
  } else if (testcase.operation === 'ECC_Point_Sub') {
    result = P.subtract(Q);
    assert(result.add(Q).equals(P), 'point subtraction identity', testcase);
  } else if (testcase.operation === 'ECC_Point_Cmp') {
    assert(P.equals(P) && P.equals(Q) === (a === b), 'point comparison', testcase);
    result = P;
  } else if (testcase.operation === 'ECC_Point_Mul') {
    result = P.multiply(b);
    assert(result.equals(curve.Point.BASE.multiply(a * b % curve.Point.Fn.ORDER)), 'point multiplication identity', testcase);
  } else if (testcase.operation === 'ECC_Point_Neg') {
    result = P.negate();
    assert(result.add(P).is0(), 'point negation identity', testcase);
  } else if (testcase.operation === 'ECC_Point_Dbl') {
    result = P.double();
    assert(result.equals(P.add(P)), 'point doubling identity', testcase);
  }
  // The group identity is a valid result of subtraction (and occasionally
  // addition), but SEC1 does not encode it and assertValidity intentionally
  // rejects it. Check codecs only for encodable non-identity points.
  if (result.is0()) return Uint8Array.of(0);
  result.assertValidity();
  assert(curve.Point.fromBytes(result.toBytes(true)).equals(result), 'point codec round-trip', testcase);
  if (info.name === 'secp256k1') {
    const oracle = testcase.operation === 'ECC_Point_Mul'
      ? tinySecp.pointMultiply(P.toBytes(true), normalizedSecret(info, testcase.secretB), true)
      : undefined;
    if (oracle !== undefined) equalBytes(result.toBytes(true), oracle, 'tiny-secp256k1 WASM point oracle', testcase);
  }
  return result.toBytes(true);
}

function eccOperation(info, testcase) {
  const curve = info.curve;
  const secretA = normalizedSecret(info, testcase.secretA);
  const secretB = normalizedSecret(info, testcase.secretB);
  const publicA = curve.getPublicKey(secretA);
  const publicB = curve.getPublicKey(secretB);

  if (testcase.operation === 'ECC_PrivateToPublic') {
    if (info.kind === 'weierstrass') {
      curve.Point.fromBytes(publicA).assertValidity();
      const node = nodePublicAndSecret(info, secretA, publicA);
      if (info.name === 'secp256k1') equalBytes(publicA, tinySecp.pointFromScalar(secretA, true), 'tiny-secp256k1 WASM public key oracle', testcase);
      return node?.getPublicKey(undefined, 'compressed') ?? publicA;
    }
    if (typeof curve.utils?.isValidPublicKey === 'function') {
      assert(curve.utils.isValidPublicKey(publicA), 'public key validation', testcase);
    } else {
      assert(publicA.length === curve.lengths.publicKey, 'public key length', testcase);
    }
    return publicA;
  }
  if (testcase.operation === 'ECC_ValidatePubkey') {
    assert(curve.utils.isValidPublicKey(publicA), 'valid public key accepted', testcase);
    if (info.kind === 'weierstrass') curve.Point.fromBytes(publicA).assertValidity();
    return publicA;
  }
  if (testcase.operation === 'ECDH_Derive') {
    const sharedA = curve.getSharedSecret(secretA, publicB);
    const sharedB = curve.getSharedSecret(secretB, publicA);
    equalBytes(sharedA, sharedB, 'ECDH symmetry', testcase);
    if (info.kind === 'weierstrass') {
      const node = nodePublicAndSecret(info, secretA, publicA);
      if (node !== undefined) equalBytes(sharedA.subarray(1), node.computeSecret(publicB), 'Node/OpenSSL ECDH oracle', testcase);
    } else if (info.kind === 'montgomery' && info.jwkCurve !== undefined) {
      const a = nodeKeyPair(info, secretA, publicA);
      const b = nodeKeyPair(info, secretB, publicB);
      equalBytes(sharedA, diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey }),
        'Node native Montgomery ECDH oracle', testcase);
    }
    return sharedA;
  }
  if (testcase.operation.startsWith('ECC_Point_')) return pointOperation(info, testcase);

  const options = info.kind === 'weierstrass' ? { prehash: true, format: 'compact' } : undefined;
  const signature = curve.sign(testcase.message, secretA, options);
  assert(curve.verify(signature, testcase.message, publicA, options), 'signature verification', testcase);
  const damaged = Uint8Array.from(testcase.message);
  if (damaged.length === 0) damaged.push?.(1);
  else damaged[0] ^= 1;
  if (damaged.length > 0) assert(!curve.verify(signature, damaged, publicA, options), 'modified-message signature rejection', testcase);
  const damagedSignature = Uint8Array.from(signature);
  damagedSignature[bytesIndex(testcase.secretB, damagedSignature.length)] ^= 1;
  let acceptedDamagedSignature = false;
  try {
    acceptedDamagedSignature = curve.verify(damagedSignature, testcase.message, publicA, options);
  } catch {
    acceptedDamagedSignature = false;
  }
  assert(!acceptedDamagedSignature, 'modified-signature rejection', testcase);

  if (info.name === 'secp256k1') {
    const digest = createHash('sha256').update(testcase.message).digest();
    assert(tinySecp.verify(digest, publicA, signature), 'tiny-secp256k1 WASM signature oracle', testcase);
    equalBytes(signature, tinySecp.sign(digest, secretA), 'tiny-secp256k1 WASM deterministic signature oracle', testcase);
  }
  const nativeKeys = nodeKeyPair(info, secretA, publicA);
  if (nativeKeys !== undefined) {
    const algorithm = info.kind === 'weierstrass' ? info.nodeHash : null;
    const key = info.kind === 'weierstrass'
      ? { key: nativeKeys.publicKey, dsaEncoding: 'ieee-p1363' }
      : nativeKeys.publicKey;
    assert(nodeVerify(algorithm, testcase.message, key, signature), 'Node native signature verification oracle', testcase);
    const signingKey = info.kind === 'weierstrass'
      ? { key: nativeKeys.privateKey, dsaEncoding: 'ieee-p1363' }
      : nativeKeys.privateKey;
    const nativeSignature = nodeSign(algorithm, testcase.message, signingKey);
    const nativeVerifyOptions = info.kind === 'weierstrass' ? { ...options, lowS: false } : options;
    assert(curve.verify(nativeSignature, testcase.message, publicA, nativeVerifyOptions),
      'Node native signature generation oracle', testcase);
  }
  if (testcase.operation === 'ECDSA_Recover' && info.kind === 'weierstrass') {
    const recoveredSignature = curve.sign(testcase.message, secretA, { prehash: true, format: 'recovered' });
    const recovered = curve.recoverPublicKey(recoveredSignature, testcase.message, { prehash: true });
    equalBytes(recovered, publicA, 'ECDSA recovery', testcase);
  }
  return signature;
}

function schnorrOperation(curves, testcase) {
  const info = curves.get('secp256k1');
  const secret = normalizedSecret(info, testcase.secretA);
  const publicKey = info.schnorr.getPublicKey(secret);
  const aux = new Uint8Array(32);
  const signature = info.schnorr.sign(testcase.message, secret, aux);
  assert(info.schnorr.verify(signature, testcase.message, publicKey), 'Schnorr verification', testcase);
  assert(tinySecp.verifySchnorr(testcase.message, publicKey, signature), 'tiny-secp256k1 WASM Schnorr oracle', testcase);
  equalBytes(signature, tinySecp.signSchnorr(testcase.message, secret, aux), 'tiny-secp256k1 WASM deterministic Schnorr oracle', testcase);
  const damaged = Uint8Array.from(signature);
  damaged[bytesIndex(testcase.secretB, damaged.length)] ^= 1;
  assert(!info.schnorr.verify(damaged, testcase.message, publicKey), 'modified Schnorr signature rejection', testcase);
  return signature;
}

function materializeRawCurve(curves, testcase) {
  const info = curves.get(testcase.curve);
  const curve = info.curve;
  const secretA = normalizedSecret(info, testcase.secretA);
  const secretB = normalizedSecret(info, testcase.secretB);
  const raw = { ...testcase, mode: 'raw', matched: true };
  if (['ECC_PrivateToPublic', 'ECDSA_Sign', 'Schnorr_Sign'].includes(testcase.operation)) {
    raw.privateKey = Uint8Array.from(secretA);
  }
  if (testcase.operation === 'Schnorr_Sign') raw.aux = new Uint8Array(32);
  if (testcase.operation === 'ECC_ValidatePubkey') raw.publicKey = Uint8Array.from(curve.getPublicKey(secretA));
  if (testcase.operation === 'ECDH_Derive') {
    raw.secretKey = Uint8Array.from(secretA);
    raw.publicKey = Uint8Array.from(curve.getPublicKey(secretB));
  }
  if (testcase.operation === 'ECDSA_Verify') {
    const options = info.kind === 'weierstrass' ? { prehash: true, format: 'compact' } : undefined;
    raw.publicKey = Uint8Array.from(curve.getPublicKey(secretA));
    raw.signature = Uint8Array.from(curve.sign(testcase.message, secretA, options));
  }
  if (testcase.operation === 'ECDSA_Recover') {
    raw.signature = Uint8Array.from(curve.sign(testcase.message, secretA, { prehash: true, format: 'recovered' }));
  }
  if (testcase.operation === 'Schnorr_Verify') {
    raw.publicKey = Uint8Array.from(info.schnorr.getPublicKey(secretA));
    raw.signature = Uint8Array.from(info.schnorr.sign(testcase.message, secretA, new Uint8Array(32)));
  }
  if (testcase.operation.startsWith('ECC_Point_')) {
    const a = normalizedScalar(curve, testcase.secretA);
    const b = normalizedScalar(curve, testcase.secretB);
    raw.pointA = Uint8Array.from(curve.Point.BASE.multiply(a).toBytes(true));
    if (['ECC_Point_Add', 'ECC_Point_Sub', 'ECC_Point_Cmp'].includes(testcase.operation)) {
      raw.pointB = Uint8Array.from(curve.Point.BASE.multiply(b).toBytes(true));
    }
    if (testcase.operation === 'ECC_Point_Mul') raw.scalar = numberToBytes(b, curve.Point.Fn.BYTES);
  }
  return raw;
}

function executeRawCurve(curves, testcase) {
  const info = curves.get(testcase.curve);
  const curve = info.curve;
  if (testcase.operation === 'ECC_PrivateToPublic') {
    const publicKey = attempt(() => curve.getPublicKey(testcase.privateKey));
    if (!publicKey.accepted) return rawOutcome(false);
    assert(publicKey.value instanceof Uint8Array, 'raw public-key output shape', testcase);
    if (info.kind === 'weierstrass' || info.kind === 'edwards') curve.Point.fromBytes(publicKey.value).assertValidity();
    return rawOutcome(true, publicKey.value);
  }
  if (testcase.operation === 'ECC_ValidatePubkey') {
    const checked = attempt(() => curve.utils.isValidPublicKey(testcase.publicKey));
    if (!checked.accepted || checked.value !== true) return rawOutcome(false);
    if (info.kind === 'weierstrass' || info.kind === 'edwards') {
      const parsed = curve.Point.fromBytes(testcase.publicKey);
      parsed.assertValidity();
    }
    return rawOutcome(true, testcase.publicKey);
  }
  if (testcase.operation === 'ECDH_Derive') {
    const shared = attempt(() => curve.getSharedSecret(testcase.secretKey, testcase.publicKey));
    if (!shared.accepted) return rawOutcome(false);
    assert(shared.value instanceof Uint8Array, 'raw ECDH output shape', testcase);
    equalBytes(curve.getSharedSecret(testcase.secretKey, testcase.publicKey), shared.value,
      'raw ECDH deterministic result', testcase);
    return rawOutcome(true, shared.value);
  }
  if (testcase.operation.startsWith('ECC_Point_')) {
    const calculated = attempt(() => {
      const P = curve.Point.fromBytes(testcase.pointA);
      if (testcase.operation === 'ECC_Point_Neg') return P.negate();
      if (testcase.operation === 'ECC_Point_Dbl') return P.double();
      if (testcase.operation === 'ECC_Point_Mul') return P.multiply(bytesToNumber(testcase.scalar));
      const Q = curve.Point.fromBytes(testcase.pointB);
      if (testcase.operation === 'ECC_Point_Add') return P.add(Q);
      if (testcase.operation === 'ECC_Point_Sub') return P.subtract(Q);
      if (testcase.operation === 'ECC_Point_Cmp') return P.equals(Q);
      throw new Error('unknown raw point operation');
    });
    if (!calculated.accepted) return rawOutcome(false);
    if (typeof calculated.value === 'boolean') return rawOutcome(true, calculated.value);
    if (calculated.value.is0()) return rawOutcome(true, Uint8Array.of(0));
    calculated.value.assertValidity();
    return rawOutcome(true, calculated.value.toBytes(true));
  }
  if (testcase.operation === 'ECDSA_Sign') {
    const options = info.kind === 'weierstrass' ? { prehash: true, format: 'compact' } : undefined;
    const signed = attempt(() => curve.sign(testcase.message, testcase.privateKey, options));
    if (!signed.accepted) return rawOutcome(false);
    assert(signed.value instanceof Uint8Array, 'raw signature output shape', testcase);
    if (testcase.matched === true) {
      const publicKey = curve.getPublicKey(testcase.privateKey);
      assert(curve.verify(signed.value, testcase.message, publicKey, options),
        'raw private-key signature verification', testcase);
    }
    return rawOutcome(true, signed.value);
  }
  if (testcase.operation === 'ECDSA_Verify') {
    const options = info.kind === 'weierstrass' ? { prehash: true, format: 'compact' } : undefined;
    const verified = attempt(() => curve.verify(testcase.signature, testcase.message, testcase.publicKey, options));
    if (!verified.accepted) return rawOutcome(false);
    assert(typeof verified.value === 'boolean', 'raw signature verification result type', testcase);
    return rawOutcome(verified.value);
  }
  if (testcase.operation === 'ECDSA_Recover') {
    const recovered = attempt(() => curve.recoverPublicKey(
      testcase.signature, testcase.message, { prehash: true },
    ));
    if (!recovered.accepted) return rawOutcome(false);
    assert(recovered.value instanceof Uint8Array, 'raw ECDSA recovery output shape', testcase);
    curve.Point.fromBytes(recovered.value).assertValidity();
    return rawOutcome(true, recovered.value);
  }
  if (testcase.operation === 'Schnorr_Sign') {
    const signed = attempt(() => info.schnorr.sign(
      testcase.message, testcase.privateKey, testcase.aux,
    ));
    if (!signed.accepted) return rawOutcome(false);
    assert(signed.value instanceof Uint8Array, 'raw Schnorr signature output shape', testcase);
    if (testcase.matched === true) {
      const publicKey = info.schnorr.getPublicKey(testcase.privateKey);
      assert(info.schnorr.verify(signed.value, testcase.message, publicKey),
        'raw Schnorr private-key signature verification', testcase);
    }
    return rawOutcome(true, signed.value);
  }
  const verified = attempt(() => info.schnorr.verify(testcase.signature, testcase.message, testcase.publicKey));
  if (!verified.accepted) return rawOutcome(false);
  assert(typeof verified.value === 'boolean', 'raw Schnorr verification result type', testcase);
  const independent = attempt(() => tinySecp.verifySchnorr(testcase.message, testcase.publicKey, testcase.signature));
  if (independent.accepted) assert(independent.value === verified.value, 'raw tiny-secp256k1 Schnorr oracle', testcase);
  return rawOutcome(verified.value);
}

function blsScalars(curve, testcase) {
  const order = curve.fields.Fr.ORDER;
  return [bytesToNumber(testcase.secretA) % (order - 1n) + 1n, bytesToNumber(testcase.secretB) % (order - 1n) + 1n];
}

function fieldOperation(curve, testcase) {
  const field = testcase.operation.endsWith('_P') ? curve.fields.Fp : curve.fields.Fr;
  const modulus = field.ORDER;
  const a = bytesToNumber(testcase.secretA) % modulus;
  const b = bytesToNumber(testcase.secretB) % modulus;
  assert(field.eql(field.add(a, b), (a + b) % modulus), 'field addition oracle', testcase);
  assert(field.eql(field.mul(a, b), a * b % modulus), 'field multiplication oracle', testcase);
  assert(field.eql(field.sub(a, b), (a - b + modulus) % modulus), 'field subtraction oracle', testcase);
  if (a !== 0n) assert(field.eql(field.mul(a, field.inv(a)), 1n), 'field inversion identity', testcase);
  if (b !== 0n) {
    assert(field.eql(field.div(a, b), field.mul(a, field.inv(b))), 'field division identity', testcase);
  }
  assert(field.eql(field.sqr(a), field.mul(a, a)), 'field square identity', testcase);
  const square = field.sqr(a);
  const root = field.sqrt(square);
  assert(field.eql(field.sqr(root), square), 'field square-root identity', testcase);
  assert(field.eql(field.add(a, field.neg(a)), 0n), 'field negation identity', testcase);
  assert(field.eql(a, a) && field.eql(a, b) === (a === b), 'field equality oracle', testcase);
  assert(field.is0(a) === (a === 0n) && field.is0(0n), 'field zero oracle', testcase);
  return numberToBytes(field.mul(a, b), field.BYTES);
}

function pairingOperation(info, testcase) {
  const curve = info.curve;
  const [a, b] = blsScalars(curve, testcase);
  const P = curve.G1.Point.BASE.multiply(a);
  const Q = curve.G2.Point.BASE.multiply(b);
  const result = curve.pairing(P, Q);
  const equivalent = curve.pairing(curve.G1.Point.BASE.multiply(a * b % curve.fields.Fr.ORDER), curve.G2.Point.BASE);
  assert(curve.fields.Fp12.eql(result, equivalent), 'pairing bilinearity', testcase);
  if (testcase.curve === 'BLS12_381') {
    equalBytes(curve.fields.Fp12.toBytes(result), mclPairingBytes(P, Q), 'mcl-wasm pairing oracle', testcase);
  } else if (testcase.curve === 'alt_bn128') {
    ffPairingOracle(info, result, testcase);
  }
  if (testcase.operation === 'BLS_FinalExp') {
    const miller = curve.pairing(P, Q, false);
    assert(curve.fields.Fp12.eql(curve.fields.Fp12.finalExponentiate(miller), result), 'final exponentiation identity', testcase);
  }
  return curve.fields.Fp12.toBytes(result);
}

function blsOperation(info, testcase) {
  const curve = info.curve;
  if (testcase.operation === 'BignumCalc_Mod_BLS12_381_P' || testcase.operation === 'BignumCalc_Mod_BLS12_381_R') {
    return fieldOperation(curve, testcase);
  }
  if (testcase.operation === 'BLS_Pairing' || testcase.operation === 'BLS_FinalExp') return pairingOperation(info, testcase);
  const [a, b] = blsScalars(curve, testcase);
  const P = curve.G1.Point.BASE.multiply(a);
  const P2 = curve.G1.Point.BASE.multiply(b);
  const Q = curve.G2.Point.BASE.multiply(a);
  const Q2 = curve.G2.Point.BASE.multiply(b);
  let result;
  switch (testcase.operation) {
    case 'BLS_PrivateToPublic': {
      const secret = numberToBytes(a, curve.fields.Fr.BYTES);
      result = curve.longSignatures.getPublicKey(secret);
      assert(result.equals(P), 'BLS private/public derivation', testcase);
      break;
    }
    case 'BLS_PrivateToPublic_G2': result = Q; break;
    case 'BLS_HashToG1': result = curve.G1.hashToCurve(testcase.message, { DST: testcase.dst }); break;
    case 'BLS_HashToG2': result = curve.G2.hashToCurve(testcase.message, { DST: testcase.dst }); break;
    case 'BLS_MapToG1': result = curve.G1.mapToCurve(a); break;
    case 'BLS_MapToG2': result = curve.G2.mapToCurve([a, b]); break;
    case 'BLS_Compress_G1':
    case 'BLS_Decompress_G1': result = curve.G1.Point.fromBytes(P.toBytes(true)); assert(result.equals(P), 'G1 codec round-trip', testcase); break;
    case 'BLS_Compress_G2':
    case 'BLS_Decompress_G2': result = curve.G2.Point.fromBytes(Q.toBytes(true)); assert(result.equals(Q), 'G2 codec round-trip', testcase); break;
    case 'BLS_IsG1OnCurve': P.assertValidity(); result = P; break;
    case 'BLS_IsG2OnCurve': Q.assertValidity(); result = Q; break;
    case 'BLS_G1_Add': result = P.add(P2); assert(result.equals(curve.G1.Point.BASE.multiply((a + b) % curve.fields.Fr.ORDER)), 'G1 addition', testcase); break;
    case 'BLS_G1_Mul': result = P.multiply(b); assert(result.equals(curve.G1.Point.BASE.multiply(a * b % curve.fields.Fr.ORDER)), 'G1 multiplication', testcase); break;
    case 'BLS_G1_Neg': result = P.negate(); assert(result.add(P).is0(), 'G1 negation', testcase); break;
    case 'BLS_G1_IsEq': assert(P.equals(P) && P.equals(P2) === (a === b), 'G1 equality', testcase); result = P; break;
    case 'BLS_G2_Add': result = Q.add(Q2); assert(result.equals(curve.G2.Point.BASE.multiply((a + b) % curve.fields.Fr.ORDER)), 'G2 addition', testcase); break;
    case 'BLS_G2_Mul': result = Q.multiply(b); assert(result.equals(curve.G2.Point.BASE.multiply(a * b % curve.fields.Fr.ORDER)), 'G2 multiplication', testcase); break;
    case 'BLS_G2_Neg': result = Q.negate(); assert(result.add(Q).is0(), 'G2 negation', testcase); break;
    case 'BLS_G2_IsEq': assert(Q.equals(Q) && Q.equals(Q2) === (a === b), 'G2 equality', testcase); result = Q; break;
    case 'BLS_Aggregate_G1':
      result = curve.longSignatures.aggregatePublicKeys([P, P2]);
      assert(result.equals(P.add(P2)), 'BLS public-key aggregation', testcase);
      break;
    case 'BLS_Aggregate_G2':
      result = curve.longSignatures.aggregateSignatures([Q, Q2]);
      assert(result.equals(Q.add(Q2)), 'BLS signature aggregation', testcase);
      break;
    case 'BLS_G1_MultiExp': result = P.multiply(b).add(P2.multiply(a)); break;
    case 'BLS_Sign':
    case 'BLS_Verify': {
      if (testcase.curve !== 'BLS12_381') throw new Error('BLS signatures require BLS12-381');
      const bls = curve.longSignatures;
      const secret = numberToBytes(a, curve.fields.Fr.BYTES);
      const hashed = bls.hash(testcase.message, testcase.dst);
      const signature = bls.sign(hashed, secret);
      const publicKey = bls.getPublicKey(secret);
      assert(bls.verify(signature, hashed, publicKey), 'BLS signature verification', testcase);
      const damaged = Uint8Array.from(signature.toBytes(true));
      damaged[bytesIndex(testcase.secretB, damaged.length)] ^= 1;
      let accepted = false;
      try {
        accepted = bls.verify(damaged, hashed, publicKey);
      } catch {
        accepted = false;
      }
      assert(!accepted, 'modified BLS signature rejection', testcase);
      result = signature;
      break;
    }
    default: throw new Error(`unknown BLS operation ${testcase.operation}`);
  }
  if (result instanceof Uint8Array) return result;
  mclGroupOracle(testcase, result, P, P2, Q, Q2, a, b);
  ffGroupOracle(info, testcase, result, P, P2, Q, Q2, a, b);
  if (result.is0()) return Uint8Array.of(0);
  result.assertValidity();
  return result.toBytes(true);
}

function materializeRawBls(info, testcase) {
  const curve = info.curve;
  const [a, b] = blsScalars(curve, testcase);
  const P = curve.G1.Point.BASE.multiply(a);
  const P2 = curve.G1.Point.BASE.multiply(b);
  const Q = curve.G2.Point.BASE.multiply(a);
  const Q2 = curve.G2.Point.BASE.multiply(b);
  const raw = { ...testcase, mode: 'raw', matched: true };
  if (testcase.operation === 'BLS_PrivateToPublic' || testcase.operation === 'BLS_PrivateToPublic_G2') {
    raw.privateKey = numberToBytes(a, curve.fields.Fr.BYTES);
  } else if (testcase.operation === 'BLS_Verify') {
    const bls = curve.longSignatures;
    const secret = numberToBytes(a, curve.fields.Fr.BYTES);
    const hashed = bls.hash(testcase.message, testcase.dst);
    raw.publicKey = Uint8Array.from(bls.getPublicKey(secret).toBytes(true));
    raw.signature = Uint8Array.from(bls.sign(hashed, secret).toBytes(true));
  } else if (['BLS_Decompress_G1', 'BLS_Decompress_G2', 'BLS_IsG1OnCurve', 'BLS_IsG2OnCurve'].includes(testcase.operation)) {
    raw.point = Uint8Array.from(testcase.operation.endsWith('G2') || testcase.operation.includes('G2')
      ? Q.toBytes(true) : P.toBytes(true));
  } else {
    const g2 = testcase.operation.includes('G2');
    raw.pointA = Uint8Array.from((g2 ? Q : P).toBytes(true));
    if (['BLS_G1_Add', 'BLS_G1_IsEq', 'BLS_G2_Add', 'BLS_G2_IsEq',
      'BLS_Aggregate_G1', 'BLS_Aggregate_G2', 'BLS_G1_MultiExp'].includes(testcase.operation)) {
      raw.pointB = Uint8Array.from((g2 ? Q2 : P2).toBytes(true));
    }
    if (['BLS_G1_Mul', 'BLS_G2_Mul', 'BLS_G1_MultiExp'].includes(testcase.operation)) {
      raw.scalar = numberToBytes(b, curve.fields.Fr.BYTES);
    }
  }
  return raw;
}

function executeRawBls(info, testcase) {
  const curve = info.curve;
  if (testcase.operation === 'BLS_PrivateToPublic' || testcase.operation === 'BLS_PrivateToPublic_G2') {
    const publicKey = attempt(() => testcase.operation === 'BLS_PrivateToPublic'
      ? curve.longSignatures.getPublicKey(testcase.privateKey)
      : curve.G2.Point.BASE.multiply(bytesToNumber(testcase.privateKey)));
    if (!publicKey.accepted) return rawOutcome(false);
    publicKey.value.assertValidity();
    return rawOutcome(true, publicKey.value.toBytes(true));
  }
  if (testcase.operation === 'BLS_Verify') {
    const verified = attempt(() => {
      const hashed = curve.longSignatures.hash(testcase.message, testcase.dst);
      return curve.longSignatures.verify(testcase.signature, hashed, testcase.publicKey);
    });
    if (!verified.accepted) return rawOutcome(false);
    assert(typeof verified.value === 'boolean', 'raw BLS verification result type', testcase);
    return rawOutcome(verified.value);
  }
  const Point = testcase.operation.includes('G2') ? curve.G2.Point : curve.G1.Point;
  if (testcase.point !== undefined) {
    const parsed = attempt(() => Point.fromBytes(testcase.point));
    if (!parsed.accepted) return rawOutcome(false);
    parsed.value.assertValidity();
    equalBytes(Point.fromBytes(parsed.value.toBytes(true)).toBytes(true), parsed.value.toBytes(true),
      'raw BLS point codec round-trip', testcase);
    return rawOutcome(true, parsed.value.toBytes(true));
  }
  const calculated = attempt(() => {
    const P = Point.fromBytes(testcase.pointA);
    if (testcase.operation === 'BLS_G1_Neg' || testcase.operation === 'BLS_G2_Neg') return P.negate();
    if (testcase.operation === 'BLS_G1_Mul' || testcase.operation === 'BLS_G2_Mul') {
      return P.multiply(bytesToNumber(testcase.scalar));
    }
    const Q = Point.fromBytes(testcase.pointB);
    if (testcase.operation === 'BLS_G1_Add' || testcase.operation === 'BLS_G2_Add') return P.add(Q);
    if (testcase.operation === 'BLS_G1_IsEq' || testcase.operation === 'BLS_G2_IsEq') return P.equals(Q);
    if (testcase.operation === 'BLS_Aggregate_G1') return curve.longSignatures.aggregatePublicKeys([P, Q]);
    if (testcase.operation === 'BLS_Aggregate_G2') return curve.longSignatures.aggregateSignatures([P, Q]);
    if (testcase.operation === 'BLS_G1_MultiExp') {
      const scalar = bytesToNumber(testcase.scalar);
      return P.multiply(scalar).add(Q.multiply(scalar));
    }
    throw new Error('unknown raw BLS group operation');
  });
  if (!calculated.accepted) return rawOutcome(false);
  if (typeof calculated.value === 'boolean') return rawOutcome(true, calculated.value);
  if (calculated.value.is0()) return rawOutcome(true, Uint8Array.of(0));
  calculated.value.assertValidity();
  return rawOutcome(true, calculated.value.toBytes(true));
}

export async function createCurvesTarget(sourceDirectory) {
  const load = await packageImporter('@noble/curves', sourceDirectory);
  const [secp, nist, ed25519Module, ed448Module, misc, blsModule, bnModule, ffBn128] = await Promise.all([
    load('secp256k1.js'), load('nist.js'), load('ed25519.js'), load('ed448.js'), load('misc.js'),
    load('bls12-381.js'), load('bn254.js'), buildBn128(true),
  ]);
  equalBytes(ed25519Module.ristretto255.Point.BASE.toBytes(),
    Uint8Array.from(Buffer.from('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76', 'hex')),
    'Ristretto255 base-point encoding known answer', { operation: 'startup', curve: 'ristretto255' });
  equalBytes(ed448Module.decaf448.Point.BASE.toBytes(),
    Uint8Array.from(Buffer.from(
      '6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333',
      'hex')),
    'Decaf448 base-point encoding known answer', { operation: 'startup', curve: 'decaf448' });
  const emptyMessage = new Uint8Array();
  equalBytes(blsModule.bls12_381.G1.hashToCurve(emptyMessage).toBytes(true),
    Uint8Array.from(Buffer.from(
      'b2e0e662181bd9f8cd8ef246071357cd07a23c4391e879b49e32084dcc1a2aede123c8e8bfcde92edac229e28b719142',
      'hex')),
    'BLS12-381 G1 hash-to-curve known answer', { operation: 'startup', curve: 'BLS12_381' });
  equalBytes(blsModule.bls12_381.G2.hashToCurve(emptyMessage).toBytes(true),
    Uint8Array.from(Buffer.from(
      'a8aab303e33ed14f4a904004a92bd26ffc969c1d1e7d4b7f0c04150a73e1845a911e51a2b2d369d5cef06560c5ac9f5' +
      '715c01566993d4469805df3e1f29b536481a832bf2751b6908faed6776d062d585521889232999d72b679d6e38bb5cfff',
      'hex')),
    'BLS12-381 G2 hash-to-curve known answer', { operation: 'startup', curve: 'BLS12_381' });
  await mcl.init(mcl.BLS12_381);
  mcl.setETHserialization(true);
  const definitions = [
    ['secp256k1', secp.secp256k1, 'weierstrass', 'secp256k1', 'secp256k1', 'sha256'],
    ['secp256r1', nist.p256, 'weierstrass', 'prime256v1', 'P-256', 'sha256'],
    ['secp384r1', nist.p384, 'weierstrass', 'secp384r1', 'P-384', 'sha384'],
    ['secp521r1', nist.p521, 'weierstrass', 'secp521r1', 'P-521', 'sha512'],
    ['brainpool256r1', misc.brainpoolP256r1, 'weierstrass', 'brainpoolP256r1'],
    ['brainpool384r1', misc.brainpoolP384r1, 'weierstrass', 'brainpoolP384r1'],
    ['brainpool512r1', misc.brainpoolP512r1, 'weierstrass', 'brainpoolP512r1'],
    ['ed25519', ed25519Module.ed25519, 'edwards', undefined, 'Ed25519'],
    ['ed448', ed448Module.ed448, 'edwards', undefined, 'Ed448'],
    ['x25519', ed25519Module.x25519, 'montgomery', undefined, 'X25519'],
    ['x448', ed448Module.x448, 'montgomery', undefined, 'X448'],
  ];
  const curves = new Map(definitions.map(([name, curve, kind, nodeName, jwkCurve, nodeHash]) => [name, {
    name, curve, kind, nodeName, jwkCurve, nodeHash, secretLength: curve.lengths.secretKey,
    ...(name === 'secp256k1' ? { schnorr: secp.schnorr } : {}),
  }]));
  const pairing = new Map([
    ['BLS12_381', { name: 'BLS12_381', curve: blsModule.bls12_381 }],
    ['alt_bn128', { name: 'alt_bn128', curve: bnModule.bn254, wasm: ffBn128 }],
  ]);
  return {
    curves,
    pairing,
    descriptors: [...curves.values()].map(({ name, kind, secretLength }) => ({ name, kind, secretLength })),
    materializeRaw(testcase) {
      if (testcase.operation.startsWith('BLS_')) return materializeRawBls(pairing.get(testcase.curve), testcase);
      return materializeRawCurve(curves, testcase);
    },
    execute(testcase) {
      if (testcase.operation.startsWith('BLS_') || testcase.operation.startsWith('BignumCalc_')) {
        if (testcase.mode === 'raw') return executeRawBls(pairing.get(testcase.curve), testcase);
        return blsOperation(pairing.get(testcase.curve), testcase);
      }
      if (testcase.mode === 'raw') return executeRawCurve(curves, testcase);
      if (testcase.operation.startsWith('Schnorr_')) return schnorrOperation(curves, testcase);
      return eccOperation(curves.get(testcase.curve), testcase);
    },
  };
}
