import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import * as secp256k1 from '@noble/secp256k1';
import * as ids from './ids.js';

secp256k1.hashes.sha256 = sha256;
secp256k1.hashes.hmacSha256 = (key, message) => hmac(sha256, key, message);

function intToBytes(value, length) {
  const number = BigInt(value);
  if (number < 0n) throw new RangeError('negative integer');
  const hex = number.toString(16);
  if (hex.length > length * 2) throw new RangeError('integer does not fit');
  return hexToBytes(hex.padStart(length * 2, '0'));
}

function point(input, prefix) {
  const result = secp256k1.Point.fromAffine({
    x: BigInt(input[`${prefix}_x`]),
    y: BigInt(input[`${prefix}_y`]),
  });
  result.assertValidity();
  return result;
}

function pointResult(result) {
  if (!result.is0()) result.assertValidity();
  const { x, y } = result.toAffine();
  return JSON.stringify([x.toString(10), y.toString(10)]);
}

function OpECC_PrivateToPublic(input) {
  try {
    return pointResult(secp256k1.Point.fromBytes(secp256k1.getPublicKey(intToBytes(input.priv, 32))));
  } catch (error) {
    return;
  }
}

function OpECDSA_Sign(input) {
  try {
    const secretKey = intToBytes(input.priv, 32);
    const publicPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(secretKey)).toAffine();
    const signatureBytes = secp256k1.sign(hexToBytes(input.cleartext), secretKey, {
      format: 'compact',
      lowS: true,
      prehash: false,
    });
    const signature = secp256k1.Signature.fromBytes(signatureBytes, 'compact');
    return JSON.stringify({
      signature: [signature.r.toString(10), signature.s.toString(10)],
      pub: [publicPoint.x.toString(10), publicPoint.y.toString(10)],
    });
  } catch (error) {
    return;
  }
}

function OpECDSA_Verify(input) {
  let verified = false;
  try {
    const publicKey = secp256k1.Point.fromAffine({
      x: BigInt(input.pub_x),
      y: BigInt(input.pub_y),
    }).toBytes(false);
    const signature = concatBytes(intToBytes(input.sig_r, 32), intToBytes(input.sig_s, 32));
    verified = secp256k1.verify(signature, hexToBytes(input.cleartext), publicKey, {
      format: 'compact',
      lowS: false,
      prehash: false,
    });
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

function OpECC_Point_Add(input) {
  try {
    return pointResult(point(input, 'a').add(point(input, 'b')));
  } catch (error) {
    return;
  }
}

function OpECC_Point_Mul(input) {
  try {
    return pointResult(point(input, 'a').multiply(BigInt(input.b)));
  } catch (error) {
    return;
  }
}

function OpECC_Point_Neg(input) {
  try {
    return pointResult(point(input, 'a').negate());
  } catch (error) {
    return;
  }
}

function OpECC_Point_Dbl(input) {
  try {
    return pointResult(point(input, 'a').double());
  } catch (error) {
    return;
  }
}

const input = JSON.parse(FuzzerInput);
const operation = BigInt(input.operation);

if (ids.IsECC_PrivateToPublic(operation)) FuzzerOutput = OpECC_PrivateToPublic(input);
else if (ids.IsECDSA_Sign(operation)) FuzzerOutput = OpECDSA_Sign(input);
else if (ids.IsECDSA_Verify(operation)) FuzzerOutput = OpECDSA_Verify(input);
else if (ids.IsECC_Point_Add(operation)) FuzzerOutput = OpECC_Point_Add(input);
else if (ids.IsECC_Point_Mul(operation)) FuzzerOutput = OpECC_Point_Mul(input);
else if (ids.IsECC_Point_Neg(operation)) FuzzerOutput = OpECC_Point_Neg(input);
else if (ids.IsECC_Point_Dbl(operation)) FuzzerOutput = OpECC_Point_Dbl(input);
