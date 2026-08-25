import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import * as ids from './ids.js';

ed25519.hashes.sha512 = sha512;

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

function OpECC_PrivateToPublic(input) {
  try {
    return JSON.stringify([bytesToInt(ed25519.getPublicKey(intToBytes(input.priv, 32))), '0']);
  } catch (error) {
    return;
  }
}

function OpECDSA_Sign(input) {
  try {
    const secretKey = intToBytes(input.priv, 32);
    const publicKey = ed25519.getPublicKey(secretKey);
    const signature = ed25519.sign(hexToBytes(input.cleartext), secretKey);
    return JSON.stringify({
      signature: [bytesToInt(signature.subarray(0, 32)), bytesToInt(signature.subarray(32))],
      pub: [bytesToInt(publicKey), '0'],
    });
  } catch (error) {
    return;
  }
}

function OpECDSA_Verify(input) {
  let verified = false;
  try {
    const signature = concatBytes(intToBytes(input.sig_r, 32), intToBytes(input.sig_s, 32));
    const publicKey = intToBytes(input.pub_x, 32);
    verified = ed25519.verify(signature, hexToBytes(input.cleartext), publicKey);
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

const input = JSON.parse(FuzzerInput);
const operation = BigInt(input.operation);

if (ids.IsECC_PrivateToPublic(operation)) FuzzerOutput = OpECC_PrivateToPublic(input);
else if (ids.IsECDSA_Sign(operation)) FuzzerOutput = OpECDSA_Sign(input);
else if (ids.IsECDSA_Verify(operation)) FuzzerOutput = OpECDSA_Verify(input);
