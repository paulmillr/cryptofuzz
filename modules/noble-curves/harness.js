import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bn254 } from '@noble/curves/bn254.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/curves/utils.js';
import * as ids from './ids.js';

const BLS = bls12_381.longSignatures;

function bytesToInt(bytes) {
  const hex = bytesToHex(bytes);
  return hex.length === 0 ? '0' : BigInt(`0x${hex}`).toString(10);
}

function intToBytes(value, length) {
  const number = BigInt(value);
  if (number < 0n) throw new RangeError('negative integer');
  const hex = number.toString(16);
  if (hex.length > length * 2) throw new RangeError('integer does not fit');
  return hexToBytes(hex.padStart(length * 2, '0'));
}

function curveInfo(curveType) {
  const id = BigInt(curveType);
  if (ids.Issecp256r1(id)) return { curve: p256, kind: 'weierstrass' };
  if (ids.Issecp384r1(id)) return { curve: p384, kind: 'weierstrass' };
  if (ids.Issecp521r1(id)) return { curve: p521, kind: 'weierstrass' };
  if (ids.Issecp256k1(id)) return { curve: secp256k1, kind: 'weierstrass' };
  if (ids.Isbrainpool256r1(id)) return { curve: brainpoolP256r1, kind: 'weierstrass' };
  if (ids.Isbrainpool384r1(id)) return { curve: brainpoolP384r1, kind: 'weierstrass' };
  if (ids.Isbrainpool512r1(id)) return { curve: brainpoolP512r1, kind: 'weierstrass' };
  if (ids.Ised25519(id)) return { curve: ed25519, kind: 'edwards' };
  if (ids.Ised448(id)) return { curve: ed448, kind: 'edwards' };
  if (ids.Isx25519(id)) return { curve: x25519, kind: 'montgomery' };
  if (ids.Isx448(id)) return { curve: x448, kind: 'montgomery' };
}

function signingCurve(curveType, digestType) {
  const info = curveInfo(curveType);
  if (!info || info.kind === 'montgomery') return;
  const digest = BigInt(digestType);
  if (ids.IsNULL(digest)) return { ...info, prehash: false };
  if (info.curve === p256 && ids.IsSHA256(digest)) return { ...info, prehash: true };
  if (info.curve === p384 && ids.IsSHA384(digest)) return { ...info, prehash: true };
  if (info.curve === p521 && ids.IsSHA512(digest)) return { ...info, prehash: true };
  if (info.curve === secp256k1 && ids.IsSHA256(digest)) return { ...info, prehash: true };
  if (info.curve === brainpoolP256r1 && ids.IsSHA256(digest)) return { ...info, prehash: true };
  if (info.curve === brainpoolP384r1 && ids.IsSHA384(digest)) return { ...info, prehash: true };
  if (info.curve === brainpoolP512r1 && ids.IsSHA512(digest)) return { ...info, prehash: true };
}

function privateKey(info, value) {
  return intToBytes(value, info.curve.lengths.secretKey);
}

function pointFromAffine(info, x, y) {
  if (info.kind === 'montgomery') return;
  const point = info.curve.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });
  point.assertValidity();
  return point;
}

function pointResult(point) {
  if (!point.is0()) point.assertValidity();
  const { x, y } = point.toAffine();
  return JSON.stringify([x.toString(10), y.toString(10)]);
}

function OpECC_PrivateToPublic(input) {
  const info = curveInfo(input.curveType);
  if (!info) return;
  try {
    const publicKey = info.curve.getPublicKey(privateKey(info, input.priv));
    if (info.kind === 'weierstrass') {
      return pointResult(info.curve.Point.fromBytes(publicKey));
    }
    return JSON.stringify([bytesToInt(publicKey), '0']);
  } catch (error) {
    return;
  }
}

function OpECC_Point_Add(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return pointResult(
      pointFromAffine(info, input.a_x, input.a_y).add(pointFromAffine(info, input.b_x, input.b_y))
    );
  } catch (error) {
    return;
  }
}

function OpECC_Point_Sub(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return pointResult(
      pointFromAffine(info, input.a_x, input.a_y).subtract(pointFromAffine(info, input.b_x, input.b_y))
    );
  } catch (error) {
    return;
  }
}

function OpECC_Point_Cmp(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return JSON.stringify(
      pointFromAffine(info, input.a_x, input.a_y).equals(pointFromAffine(info, input.b_x, input.b_y))
    );
  } catch (error) {
    return;
  }
}

function OpECC_Point_Dbl(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return pointResult(pointFromAffine(info, input.a_x, input.a_y).double());
  } catch (error) {
    return;
  }
}

function OpECC_Point_Neg(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return pointResult(pointFromAffine(info, input.a_x, input.a_y).negate());
  } catch (error) {
    return;
  }
}

function OpECC_Point_Mul(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  try {
    return pointResult(pointFromAffine(info, input.a_x, input.a_y).multiply(BigInt(input.b)));
  } catch (error) {
    return;
  }
}

function OpECC_ValidatePubkey(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'montgomery') return;
  let valid = false;
  try {
    if (info.kind === 'weierstrass') {
      valid = info.curve.utils.isValidPublicKey(pointFromAffine(info, input.pub_x, input.pub_y).toBytes(false));
    } else {
      valid = info.curve.utils.isValidPublicKey(intToBytes(input.pub_x, info.curve.lengths.publicKey));
    }
  } catch (error) {
    valid = false;
  }
  return JSON.stringify(valid);
}

function OpECDH_Derive(input) {
  const info = curveInfo(input.curveType);
  if (!info || info.kind === 'edwards') return;
  try {
    const secretKey = privateKey(info, input.priv);
    if (info.kind === 'montgomery') {
      const publicKey = intToBytes(input.pub_x, info.curve.lengths.publicKey);
      return JSON.stringify(bytesToHex(info.curve.getSharedSecret(secretKey, publicKey)));
    }
    const publicKey = pointFromAffine(info, input.pub_x, input.pub_y).toBytes(false);
    const sharedPoint = info.curve.Point.fromBytes(info.curve.getSharedSecret(secretKey, publicKey, false));
    return JSON.stringify(bytesToHex(intToBytes(sharedPoint.toAffine().x, info.curve.Point.Fp.BYTES)));
  } catch (error) {
    return;
  }
}

function OpECDSA_Sign(input) {
  const info = signingCurve(input.curveType, input.digestType);
  if (!info) return;
  try {
    const message = hexToBytes(input.cleartext);
    const secretKey = privateKey(info, input.priv);
    const publicKey = info.curve.getPublicKey(secretKey);
    if (info.kind === 'edwards') {
      const signature = info.curve.sign(message, secretKey);
      const half = signature.length / 2;
      return JSON.stringify({
        signature: [bytesToInt(signature.subarray(0, half)), bytesToInt(signature.subarray(half))],
        pub: [bytesToInt(publicKey), '0'],
      });
    }
    const signatureBytes = info.curve.sign(message, secretKey, {
      format: 'compact',
      lowS: true,
      prehash: info.prehash,
    });
    const signature = info.curve.Signature.fromBytes(signatureBytes, 'compact');
    const publicPoint = info.curve.Point.fromBytes(publicKey).toAffine();
    return JSON.stringify({
      signature: [signature.r.toString(10), signature.s.toString(10)],
      pub: [publicPoint.x.toString(10), publicPoint.y.toString(10)],
    });
  } catch (error) {
    return;
  }
}

function OpECDSA_Verify(input) {
  const info = signingCurve(input.curveType, input.digestType);
  if (!info) return;
  let verified = false;
  try {
    const message = hexToBytes(input.cleartext);
    if (info.kind === 'edwards') {
      const half = info.curve.lengths.signature / 2;
      const signature = concatBytes(intToBytes(input.sig_r, half), intToBytes(input.sig_s, half));
      const publicKey = intToBytes(input.pub_x, info.curve.lengths.publicKey);
      verified = info.curve.verify(signature, message, publicKey);
    } else {
      const publicKey = pointFromAffine(info, input.pub_x, input.pub_y).toBytes(false);
      const signature = new info.curve.Signature(BigInt(input.sig_r), BigInt(input.sig_s));
      verified = info.curve.verify(signature.toBytes('compact'), message, publicKey, {
        format: 'compact',
        lowS: false,
        prehash: info.prehash,
      });
    }
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

function OpECDSA_Recover(input) {
  const info = signingCurve(input.curveType, input.digestType);
  if (!info || info.kind !== 'weierstrass') return;
  try {
    const signature = new info.curve.Signature(BigInt(input.sig_r), BigInt(input.sig_s), Number(input.id));
    const publicKey = info.curve.recoverPublicKey(
      signature.toBytes('recovered'),
      hexToBytes(input.cleartext),
      { prehash: info.prehash }
    );
    return pointResult(info.curve.Point.fromBytes(publicKey));
  } catch (error) {
    return;
  }
}

function schnorrMessage(input) {
  const digest = BigInt(input.digestType);
  const message = hexToBytes(input.cleartext);
  if (ids.IsNULL(digest)) return message;
  if (ids.IsSHA256(digest)) return secp256k1.hash(message);
}

function OpSchnorr_Sign(input) {
  if (!ids.Issecp256k1(BigInt(input.curveType)) || Number(input.nonceSource) !== 1) return;
  const message = schnorrMessage(input);
  if (!message) return;
  try {
    const secretKey = intToBytes(input.priv, 32);
    const signature = schnorr.sign(message, secretKey, new Uint8Array(32));
    return JSON.stringify({
      signature: [bytesToInt(signature.subarray(0, 32)), bytesToInt(signature.subarray(32))],
      pub: [bytesToInt(schnorr.getPublicKey(secretKey)), '0'],
    });
  } catch (error) {
    return;
  }
}

function OpSchnorr_Verify(input) {
  if (!ids.Issecp256k1(BigInt(input.curveType))) return;
  const message = schnorrMessage(input);
  if (!message) return;
  let verified = false;
  try {
    const signature = concatBytes(intToBytes(input.sig_r, 32), intToBytes(input.sig_s, 32));
    verified = schnorr.verify(signature, message, intToBytes(input.pub_x, 32));
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

function isBLS12_381(input) {
  return ids.IsBLS12_381(BigInt(input.curveType));
}

function pairingCurve(input) {
  const id = BigInt(input.curveType);
  if (ids.IsBLS12_381(id)) return bls12_381;
  if (ids.Isalt_bn128(id)) return bn254;
}

function dstBytes(input) {
  return hexToBytes(input.dest);
}

function To_G1(x, y, curve = bls12_381) {
  const point = curve.G1.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });
  point.assertValidity();
  return point;
}

function From_G1(point) {
  const { x, y } = point.toAffine();
  return [x.toString(10), y.toString(10)];
}

function To_G2(v, w, x, y, curve = bls12_381) {
  const point = curve.G2.Point.fromAffine({
    x: curve.fields.Fp2.create({ c0: BigInt(v), c1: BigInt(x) }),
    y: curve.fields.Fp2.create({ c0: BigInt(w), c1: BigInt(y) }),
  });
  point.assertValidity();
  return point;
}

function From_G2(point) {
  const affine = point.toAffine();
  return [
    [affine.x.c0.toString(10), affine.y.c0.toString(10)],
    [affine.x.c1.toString(10), affine.y.c1.toString(10)],
  ];
}

function blsPrivateKey(value) {
  return intToBytes(value, bls12_381.fields.Fr.BYTES);
}

function OpBLS_PrivateToPublic(input) {
  if (!isBLS12_381(input)) return;
  try {
    return JSON.stringify(From_G1(BLS.getPublicKey(blsPrivateKey(input.priv))));
  } catch (error) {
    return;
  }
}

function OpBLS_PrivateToPublic_G2(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_G2(curve.G2.Point.BASE.multiply(BigInt(input.priv))));
  } catch (error) {
    return;
  }
}

function From_Fp12(value) {
  return [
    value.c0.c0.c0, value.c0.c0.c1,
    value.c0.c1.c0, value.c0.c1.c1,
    value.c0.c2.c0, value.c0.c2.c1,
    value.c1.c0.c0, value.c1.c0.c1,
    value.c1.c1.c0, value.c1.c1.c1,
    value.c1.c2.c0, value.c1.c2.c1,
  ].map((item) => item.toString(10));
}

function To_Fp12(curve, values) {
  if (!Array.isArray(values) || values.length !== 12) throw new TypeError('invalid Fp12');
  const fp2 = (offset) => curve.fields.Fp2.create({
    c0: BigInt(values[offset]),
    c1: BigInt(values[offset + 1]),
  });
  const fp6 = (offset) => curve.fields.Fp6.create({
    c0: fp2(offset),
    c1: fp2(offset + 2),
    c2: fp2(offset + 4),
  });
  return curve.fields.Fp12.create({ c0: fp6(0), c1: fp6(6) });
}

function OpBLS_Pairing(input, withFinalExponent) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    const g1 = To_G1(input.g1_x, input.g1_y, curve);
    const g2 = To_G2(input.g2_v, input.g2_w, input.g2_x, input.g2_y, curve);
    return JSON.stringify(From_Fp12(curve.pairing(g1, g2, withFinalExponent)));
  } catch (error) {
    return;
  }
}

function OpBLS_FinalExp(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_Fp12(curve.fields.Fp12.finalExponentiate(To_Fp12(curve, input.fp12))));
  } catch (error) {
    return;
  }
}

function OpBLS_MapToG1(input) {
  if (!isBLS12_381(input)) return;
  try {
    const point = bls12_381.G1.mapToCurve(BigInt(input.u)).add(
      bls12_381.G1.mapToCurve(BigInt(input.v))
    );
    return JSON.stringify(From_G1(point));
  } catch (error) {
    return;
  }
}

function OpBLS_MapToG2(input) {
  if (!isBLS12_381(input)) return;
  try {
    const point = bls12_381.G2.mapToCurve([BigInt(input.u_x), BigInt(input.u_y)]).add(
      bls12_381.G2.mapToCurve([BigInt(input.v_x), BigInt(input.v_y)])
    );
    return JSON.stringify(From_G2(point));
  } catch (error) {
    return;
  }
}

function OpBLS_G1_MultiExp(input) {
  const curve = pairingCurve(input);
  if (!curve || !Array.isArray(input.points_scalars) || input.points_scalars.length === 0) return;
  try {
    let result = curve.G1.Point.ZERO;
    for (const item of input.points_scalars) {
      result = result.add(To_G1(item.x, item.y, curve).multiply(BigInt(item.scalar)));
    }
    return JSON.stringify(From_G1(result));
  } catch (error) {
    return;
  }
}

function OpBLS_HashToG1(input) {
  if (!isBLS12_381(input)) return;
  try {
    const message = hexToBytes(input.aug + input.cleartext);
    return JSON.stringify(From_G1(bls12_381.G1.hashToCurve(message, { DST: dstBytes(input) })));
  } catch (error) {
    return;
  }
}

function OpBLS_HashToG2(input) {
  if (!isBLS12_381(input)) return;
  try {
    const message = hexToBytes(input.aug + input.cleartext);
    return JSON.stringify(From_G2(bls12_381.G2.hashToCurve(message, { DST: dstBytes(input) })));
  } catch (error) {
    return;
  }
}

function OpBLS_Sign(input) {
  if (!isBLS12_381(input)) return;
  try {
    const DST = dstBytes(input);
    const message = input.hashOrPoint
      ? BLS.hash(hexToBytes(input.aug + input.cleartext), DST)
      : To_G2(input.g2_v, input.g2_w, input.g2_x, input.g2_y);
    const secretKey = blsPrivateKey(input.priv);
    return JSON.stringify({
      signature: From_G2(BLS.sign(message, secretKey)),
      pub: From_G1(BLS.getPublicKey(secretKey)),
    });
  } catch (error) {
    return;
  }
}

function OpBLS_Verify(input) {
  if (!isBLS12_381(input)) return;
  let verified = false;
  try {
    const message = BLS.hash(hexToBytes(input.cleartext), dstBytes(input));
    const signature = To_G2(input.g2_v, input.g2_w, input.g2_x, input.g2_y);
    const publicKey = To_G1(input.g1_x, input.g1_y);
    verified = BLS.verify(signature, message, publicKey);
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

function OpBLS_Compress_G1(input) {
  if (!isBLS12_381(input)) return;
  try {
    return JSON.stringify(bytesToInt(To_G1(input.g1_x, input.g1_y).toBytes(true)));
  } catch (error) {
    return;
  }
}

function OpBLS_Decompress_G1(input) {
  if (!isBLS12_381(input)) return;
  try {
    const point = bls12_381.G1.Point.fromBytes(intToBytes(input.compressed, 48));
    point.assertValidity();
    return JSON.stringify(From_G1(point));
  } catch (error) {
    return;
  }
}

function OpBLS_Compress_G2(input) {
  if (!isBLS12_381(input)) return;
  try {
    const compressed = To_G2(input.g2_v, input.g2_w, input.g2_x, input.g2_y).toBytes(true);
    return JSON.stringify([bytesToInt(compressed.subarray(0, 48)), bytesToInt(compressed.subarray(48))]);
  } catch (error) {
    return;
  }
}

function OpBLS_Decompress_G2(input) {
  if (!isBLS12_381(input)) return;
  try {
    const compressed = concatBytes(intToBytes(input.g1_x, 48), intToBytes(input.g1_y, 48));
    const point = bls12_381.G2.Point.fromBytes(compressed);
    point.assertValidity();
    return JSON.stringify(From_G2(point));
  } catch (error) {
    return;
  }
}

function OpBLS_IsG1OnCurve(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  let valid = false;
  try {
    valid = !To_G1(input.g1_x, input.g1_y, curve).is0();
  } catch (error) {
    valid = false;
  }
  return JSON.stringify(valid);
}

function OpBLS_IsG2OnCurve(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  let valid = false;
  try {
    valid = !To_G2(input.g2_v, input.g2_w, input.g2_x, input.g2_y, curve).is0();
  } catch (error) {
    valid = false;
  }
  return JSON.stringify(valid);
}

function OpBLS_G1_Add(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_G1(
      To_G1(input.a_x, input.a_y, curve).add(To_G1(input.b_x, input.b_y, curve))
    ));
  } catch (error) {
    return;
  }
}

function OpBLS_G1_Mul(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_G1(To_G1(input.a_x, input.a_y, curve).multiply(BigInt(input.b))));
  } catch (error) {
    return;
  }
}

function OpBLS_G1_Neg(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_G1(To_G1(input.a_x, input.a_y, curve).negate()));
  } catch (error) {
    return;
  }
}

function OpBLS_G1_IsEq(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  let equal = false;
  try {
    equal = To_G1(input.a_x, input.a_y, curve).equals(To_G1(input.b_x, input.b_y, curve));
  } catch (error) {
    equal = false;
  }
  return JSON.stringify(equal);
}

function OpBLS_G2_Add(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    const a = To_G2(input.a_v, input.a_w, input.a_x, input.a_y, curve);
    const b = To_G2(input.b_v, input.b_w, input.b_x, input.b_y, curve);
    return JSON.stringify(From_G2(a.add(b)));
  } catch (error) {
    return;
  }
}

function OpBLS_G2_Mul(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    const point = To_G2(input.a_v, input.a_w, input.a_x, input.a_y, curve);
    return JSON.stringify(From_G2(point.multiply(BigInt(input.b))));
  } catch (error) {
    return;
  }
}

function OpBLS_G2_Neg(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  try {
    return JSON.stringify(From_G2(To_G2(input.a_v, input.a_w, input.a_x, input.a_y, curve).negate()));
  } catch (error) {
    return;
  }
}

function OpBLS_G2_IsEq(input) {
  const curve = pairingCurve(input);
  if (!curve) return;
  let equal = false;
  try {
    const a = To_G2(input.a_v, input.a_w, input.a_x, input.a_y, curve);
    const b = To_G2(input.b_v, input.b_w, input.b_x, input.b_y, curve);
    equal = a.equals(b);
  } catch (error) {
    equal = false;
  }
  return JSON.stringify(equal);
}

function OpBLS_Aggregate_G1(input) {
  if (!isBLS12_381(input)) return;
  try {
    const points = input.points.map((point) => To_G1(point.x, point.y));
    return JSON.stringify(From_G1(BLS.aggregatePublicKeys(points)));
  } catch (error) {
    return;
  }
}

function OpBLS_Aggregate_G2(input) {
  if (!isBLS12_381(input)) return;
  try {
    const points = input.points.map((point) => To_G2(point.v, point.w, point.x, point.y));
    return JSON.stringify(From_G2(BLS.aggregateSignatures(points)));
  } catch (error) {
    return;
  }
}

function OpBignumCalc(input, field) {
  try {
    const operation = BigInt(input.calcOp);
    const a = field.create(BigInt(input.bn0));
    const b = field.create(BigInt(input.bn1));
    let result;
    if (ids.IsAdd(operation)) result = field.add(a, b);
    else if (ids.IsSub(operation)) result = field.sub(a, b);
    else if (ids.IsMul(operation)) result = field.mul(a, b);
    else if (ids.IsDiv(operation)) result = field.div(a, b);
    else if (ids.IsSqr(operation)) result = field.sqr(a);
    else if (ids.IsInvMod(operation)) result = field.inv(a);
    else if (ids.IsSqrt(operation)) result = field.sqr(field.sqrt(a));
    else if (ids.IsNeg(operation)) result = field.neg(a);
    else if (ids.IsIsEq(operation)) result = field.eql(a, b) ? 1n : 0n;
    else if (ids.IsIsZero(operation)) result = field.is0(a) ? 1n : 0n;
    else return;
    return JSON.stringify(result.toString(10));
  } catch (error) {
    return;
  }
}

const input = JSON.parse(FuzzerInput);
const operation = BigInt(input.operation);

if (ids.IsECC_PrivateToPublic(operation)) FuzzerOutput = OpECC_PrivateToPublic(input);
else if (ids.IsECC_ValidatePubkey(operation)) FuzzerOutput = OpECC_ValidatePubkey(input);
else if (ids.IsECDH_Derive(operation)) FuzzerOutput = OpECDH_Derive(input);
else if (ids.IsECDSA_Sign(operation)) FuzzerOutput = OpECDSA_Sign(input);
else if (ids.IsECDSA_Verify(operation)) FuzzerOutput = OpECDSA_Verify(input);
else if (ids.IsECDSA_Recover(operation)) FuzzerOutput = OpECDSA_Recover(input);
else if (ids.IsSchnorr_Sign(operation)) FuzzerOutput = OpSchnorr_Sign(input);
else if (ids.IsSchnorr_Verify(operation)) FuzzerOutput = OpSchnorr_Verify(input);
else if (ids.IsECC_Point_Add(operation)) FuzzerOutput = OpECC_Point_Add(input);
else if (ids.IsECC_Point_Sub(operation)) FuzzerOutput = OpECC_Point_Sub(input);
else if (ids.IsECC_Point_Cmp(operation)) FuzzerOutput = OpECC_Point_Cmp(input);
else if (ids.IsECC_Point_Mul(operation)) FuzzerOutput = OpECC_Point_Mul(input);
else if (ids.IsECC_Point_Neg(operation)) FuzzerOutput = OpECC_Point_Neg(input);
else if (ids.IsECC_Point_Dbl(operation)) FuzzerOutput = OpECC_Point_Dbl(input);
else if (ids.IsBLS_PrivateToPublic(operation)) FuzzerOutput = OpBLS_PrivateToPublic(input);
else if (ids.IsBLS_PrivateToPublic_G2(operation)) FuzzerOutput = OpBLS_PrivateToPublic_G2(input);
else if (ids.IsBLS_HashToG1(operation)) FuzzerOutput = OpBLS_HashToG1(input);
else if (ids.IsBLS_HashToG2(operation)) FuzzerOutput = OpBLS_HashToG2(input);
else if (ids.IsBLS_MapToG1(operation)) FuzzerOutput = OpBLS_MapToG1(input);
else if (ids.IsBLS_MapToG2(operation)) FuzzerOutput = OpBLS_MapToG2(input);
else if (ids.IsBLS_Sign(operation)) FuzzerOutput = OpBLS_Sign(input);
else if (ids.IsBLS_Verify(operation)) FuzzerOutput = OpBLS_Verify(input);
else if (ids.IsBLS_Pairing(operation)) FuzzerOutput = OpBLS_Pairing(input, true);
else if (ids.IsBLS_FinalExp(operation)) FuzzerOutput = OpBLS_FinalExp(input);
else if (ids.IsBLS_Compress_G1(operation)) FuzzerOutput = OpBLS_Compress_G1(input);
else if (ids.IsBLS_Decompress_G1(operation)) FuzzerOutput = OpBLS_Decompress_G1(input);
else if (ids.IsBLS_Compress_G2(operation)) FuzzerOutput = OpBLS_Compress_G2(input);
else if (ids.IsBLS_Decompress_G2(operation)) FuzzerOutput = OpBLS_Decompress_G2(input);
else if (ids.IsBLS_IsG1OnCurve(operation)) FuzzerOutput = OpBLS_IsG1OnCurve(input);
else if (ids.IsBLS_IsG2OnCurve(operation)) FuzzerOutput = OpBLS_IsG2OnCurve(input);
else if (ids.IsBLS_G1_Add(operation)) FuzzerOutput = OpBLS_G1_Add(input);
else if (ids.IsBLS_G1_Mul(operation)) FuzzerOutput = OpBLS_G1_Mul(input);
else if (ids.IsBLS_G1_Neg(operation)) FuzzerOutput = OpBLS_G1_Neg(input);
else if (ids.IsBLS_G1_IsEq(operation)) FuzzerOutput = OpBLS_G1_IsEq(input);
else if (ids.IsBLS_G2_Add(operation)) FuzzerOutput = OpBLS_G2_Add(input);
else if (ids.IsBLS_G2_Mul(operation)) FuzzerOutput = OpBLS_G2_Mul(input);
else if (ids.IsBLS_G2_Neg(operation)) FuzzerOutput = OpBLS_G2_Neg(input);
else if (ids.IsBLS_G2_IsEq(operation)) FuzzerOutput = OpBLS_G2_IsEq(input);
else if (ids.IsBLS_Aggregate_G1(operation)) FuzzerOutput = OpBLS_Aggregate_G1(input);
else if (ids.IsBLS_Aggregate_G2(operation)) FuzzerOutput = OpBLS_Aggregate_G2(input);
else if (ids.IsBLS_G1_MultiExp(operation)) FuzzerOutput = OpBLS_G1_MultiExp(input);
else if (ids.IsBignumCalc_Mod_BLS12_381_P(operation)) {
  FuzzerOutput = OpBignumCalc(input, bls12_381.fields.Fp);
} else if (ids.IsBignumCalc_Mod_BLS12_381_R(operation)) {
  FuzzerOutput = OpBignumCalc(input, bls12_381.fields.Fr);
}
