import { aeskw, aeskwp, aessiv, cbc, cfb, ctr, ecb, gcm, gcmsiv } from '@noble/ciphers/aes.js';
import { chacha20, chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { salsa20 } from '@noble/ciphers/salsa.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/ciphers/utils.js';
import * as ids from './ids.js';

const TAG_LENGTH = 16;
const AES_BLOCK_LENGTH = 16;
const AES_KW_IV = hexToBytes('a6a6a6a6a6a6a6a6');

const SPECS = [
  { is: ids.IsAES_128_ECB, kind: 'ecb', keyLength: 16 },
  { is: ids.IsAES_192_ECB, kind: 'ecb', keyLength: 24 },
  { is: ids.IsAES_256_ECB, kind: 'ecb', keyLength: 32 },
  { is: ids.IsAES_128_CBC, kind: 'cbc', keyLength: 16, ivLength: 16 },
  { is: ids.IsAES_192_CBC, kind: 'cbc', keyLength: 24, ivLength: 16 },
  { is: ids.IsAES_256_CBC, kind: 'cbc', keyLength: 32, ivLength: 16 },
  { is: ids.IsAES_128_CTR, kind: 'ctr', keyLength: 16, ivLength: 16 },
  { is: ids.IsAES_192_CTR, kind: 'ctr', keyLength: 24, ivLength: 16 },
  { is: ids.IsAES_256_CTR, kind: 'ctr', keyLength: 32, ivLength: 16 },
  { is: ids.IsAES_128_CFB, kind: 'cfb', keyLength: 16, ivLength: 16 },
  { is: ids.IsAES_192_CFB, kind: 'cfb', keyLength: 24, ivLength: 16 },
  { is: ids.IsAES_256_CFB, kind: 'cfb', keyLength: 32, ivLength: 16 },
  { is: ids.IsAES_128_CFB128, kind: 'cfb', keyLength: 16, ivLength: 16 },
  { is: ids.IsAES_192_CFB128, kind: 'cfb', keyLength: 24, ivLength: 16 },
  { is: ids.IsAES_256_CFB128, kind: 'cfb', keyLength: 32, ivLength: 16 },
  { is: ids.IsAES_128_GCM, kind: 'gcm', keyLength: 16, aead: true },
  { is: ids.IsAES_192_GCM, kind: 'gcm', keyLength: 24, aead: true },
  { is: ids.IsAES_256_GCM, kind: 'gcm', keyLength: 32, aead: true },
  { is: ids.IsAES_128_GCM_SIV, kind: 'gcmsiv', keyLength: 16, ivLength: 12, aead: true },
  { is: ids.IsAES_256_GCM_SIV, kind: 'gcmsiv', keyLength: 32, ivLength: 12, aead: true },
  { is: ids.IsAES_128_SIV_CMAC, kind: 'aessiv', keyLength: 32, aead: true, tagAtStart: true },
  { is: ids.IsAES_192_SIV_CMAC, kind: 'aessiv', keyLength: 48, aead: true, tagAtStart: true },
  { is: ids.IsAES_256_SIV_CMAC, kind: 'aessiv', keyLength: 64, aead: true, tagAtStart: true },
  { is: ids.IsAES_128_WRAP, kind: 'aeskw', keyLength: 16 },
  { is: ids.IsAES_192_WRAP, kind: 'aeskw', keyLength: 24 },
  { is: ids.IsAES_256_WRAP, kind: 'aeskw', keyLength: 32 },
  { is: ids.IsAES_128_WRAP_PAD, kind: 'aeskwp', keyLength: 16 },
  { is: ids.IsAES_192_WRAP_PAD, kind: 'aeskwp', keyLength: 24 },
  { is: ids.IsAES_256_WRAP_PAD, kind: 'aeskwp', keyLength: 32 },
  { is: ids.IsCHACHA20, kind: 'chacha20', keyLength: 32, ivLength: 12, stream: true },
  { is: ids.IsCHACHA20_POLY1305, kind: 'chacha20poly1305', keyLength: 32, ivLength: 12, aead: true },
  { is: ids.IsXCHACHA20_POLY1305, kind: 'xchacha20poly1305', keyLength: 32, ivLength: 24, aead: true },
  { is: ids.IsSALSA20_128, kind: 'salsa20', keyLength: 16, ivLength: 8, stream: true },
  { is: ids.IsSALSA20_256, kind: 'salsa20', keyLength: 32, ivLength: 8, stream: true },
];

function specFor(cipherType) {
  return SPECS.find((spec) => spec.is(cipherType));
}

function isSafeSize(value) {
  const size = Number(value);
  return Number.isSafeInteger(size) && size >= 0 ? size : undefined;
}

function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function validWrapIv(kind, iv) {
  if (iv.length === 0) return true;
  if (kind !== 'aeskw') return false;
  if (iv.length !== 8 && iv.length !== 16) return false;
  return equalBytes(iv.subarray(0, AES_KW_IV.length), AES_KW_IV);
}

function validOptions(spec, input, encrypting) {
  if (spec.aead) {
    if (encrypting) {
      return input.tagSize_enabled === true && isSafeSize(input.tagSize) === TAG_LENGTH;
    }
    if (input.tag_enabled !== true) return false;
    return hexToBytes(input.tag).length === TAG_LENGTH;
  }

  if (input.aad_enabled === true) return false;
  if (encrypting) return input.tagSize_enabled !== true;
  return input.tag_enabled !== true;
}

function makeCipher(spec, key, iv, input) {
  const aad = input.aad_enabled === true ? hexToBytes(input.aad) : undefined;
  switch (spec.kind) {
    case 'ecb':
      return ecb(key, { disablePadding: true });
    case 'cbc':
      return cbc(key, iv);
    case 'ctr':
      return ctr(key, iv);
    case 'cfb':
      return cfb(key, iv);
    case 'gcm':
      return gcm(key, iv, aad);
    case 'gcmsiv':
      return gcmsiv(key, iv, aad);
    case 'aessiv': {
      // Cryptofuzz's native AES-SIV adapters expose one AAD component and an
      // optional nonce. Even an absent AAD is passed as the empty component;
      // a zero-length IV means that the optional nonce component is absent.
      const associated = [aad === undefined ? new Uint8Array() : aad];
      if (iv.length !== 0) associated.push(iv);
      return aessiv(key, ...associated);
    }
    case 'aeskw':
      return aeskw(key);
    case 'aeskwp':
      return aeskwp(key);
    case 'chacha20poly1305':
      return chacha20poly1305(key, iv, aad);
    case 'xchacha20poly1305':
      return xchacha20poly1305(key, iv, aad);
  }
}

function processStream(spec, key, iv, data) {
  if (spec.kind === 'chacha20') return chacha20(key, iv, data);
  if (spec.kind === 'salsa20') return salsa20(key, iv, data);
}

function validateInputs(spec, key, iv) {
  if (key.length !== spec.keyLength) return false;
  if (spec.ivLength !== undefined && iv.length !== spec.ivLength) return false;
  if (spec.kind === 'gcm' && iv.length < 8) return false;
  if ((spec.kind === 'aeskw' || spec.kind === 'aeskwp') && !validWrapIv(spec.kind, iv)) return false;
  return true;
}

function OpSymmetricEncrypt(input) {
  const spec = specFor(BigInt(input.cipher.cipherType));
  if (!spec) return;

  try {
    const cleartext = hexToBytes(input.cleartext);
    const key = hexToBytes(input.cipher.key);
    const iv = hexToBytes(input.cipher.iv);
    const capacity = isSafeSize(input.ciphertextSize);
    if (capacity === undefined || !validateInputs(spec, key, iv) || !validOptions(spec, input, true)) return;

    if (spec.kind === 'ecb' && cleartext.length % AES_BLOCK_LENGTH !== 0) return;
    if (spec.kind === 'aeskw' && (cleartext.length < 16 || cleartext.length % 8 !== 0)) return;
    if (spec.kind === 'aeskwp' && cleartext.length === 0) return;

    const combined = spec.stream
      ? processStream(spec, key, iv, cleartext)
      : makeCipher(spec, key, iv, input).encrypt(cleartext);

    if (!spec.aead) {
      if (combined.length > capacity) return;
      return JSON.stringify({ ciphertext: bytesToHex(combined) });
    }

    const tag = spec.tagAtStart
      ? combined.subarray(0, TAG_LENGTH)
      : combined.subarray(combined.length - TAG_LENGTH);
    const ciphertext = spec.tagAtStart
      ? combined.subarray(TAG_LENGTH)
      : combined.subarray(0, combined.length - TAG_LENGTH);
    if (ciphertext.length > capacity) return;
    return JSON.stringify({ ciphertext: bytesToHex(ciphertext), tag: bytesToHex(tag) });
  } catch (error) {
    return;
  }
}

function OpSymmetricDecrypt(input) {
  const spec = specFor(BigInt(input.cipher.cipherType));
  if (!spec) return;

  try {
    const ciphertext = hexToBytes(input.ciphertext);
    const key = hexToBytes(input.cipher.key);
    const iv = hexToBytes(input.cipher.iv);
    const capacity = isSafeSize(input.cleartextSize);
    if (capacity === undefined || !validateInputs(spec, key, iv) || !validOptions(spec, input, false)) return;

    if (spec.kind === 'ecb' && ciphertext.length % AES_BLOCK_LENGTH !== 0) return;
    if (spec.kind === 'cbc' && (ciphertext.length === 0 || ciphertext.length % AES_BLOCK_LENGTH !== 0)) return;
    if (spec.kind === 'aeskw' && (ciphertext.length < 24 || ciphertext.length % 8 !== 0)) return;
    if (spec.kind === 'aeskwp' && (ciphertext.length < 16 || ciphertext.length % 8 !== 0)) return;

    let cleartext;
    if (spec.stream) {
      cleartext = processStream(spec, key, iv, ciphertext);
    } else {
      let combined = ciphertext;
      if (spec.aead) {
        const tag = hexToBytes(input.tag);
        combined = spec.tagAtStart ? concatBytes(tag, ciphertext) : concatBytes(ciphertext, tag);
      }
      cleartext = makeCipher(spec, key, iv, input).decrypt(combined);
    }
    if (cleartext.length > capacity) return;
    return JSON.stringify(bytesToHex(cleartext));
  } catch (error) {
    return;
  }
}

const input = JSON.parse(FuzzerInput);
const operation = BigInt(input.operation);

if (ids.IsSymmetricEncrypt(operation)) FuzzerOutput = OpSymmetricEncrypt(input);
else if (ids.IsSymmetricDecrypt(operation)) FuzzerOutput = OpSymmetricDecrypt(input);
