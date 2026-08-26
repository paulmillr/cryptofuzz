import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { argon2d, argon2i, argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { scrypt } from '@noble/hashes/scrypt.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import {
  keccak_224,
  keccak_256,
  keccak_384,
  keccak_512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
} from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as ids from './ids.js';

function configuredHash(hash, options) {
  const configured = (message) => hash(message, options);
  const instance = hash.create(options);
  configured.outputLen = instance.outputLen;
  configured.blockLen = instance.blockLen;
  configured.canXOF = instance.canXOF;
  configured.create = () => hash.create(options);
  return configured;
}

const blake2s128 = configuredHash(blake2s, { dkLen: 16 });
const blake2s160 = configuredHash(blake2s, { dkLen: 20 });
const blake2s224 = configuredHash(blake2s, { dkLen: 28 });
const blake2b128 = configuredHash(blake2b, { dkLen: 16 });
const blake2b160 = configuredHash(blake2b, { dkLen: 20 });
const blake2b256 = configuredHash(blake2b, { dkLen: 32 });
const blake2b384 = configuredHash(blake2b, { dkLen: 48 });
const shake128Digest = configuredHash(shake128, { dkLen: 16 });
const shake128Kdf = configuredHash(shake128, { dkLen: 32 });
const shake256Digest = configuredHash(shake256, { dkLen: 32 });
const shake256Kdf = configuredHash(shake256, { dkLen: 64 });
const shake256_114 = configuredHash(shake256, { dkLen: 114 });

function hashFor(digestType, altShake = false) {
  const digest = digestType;
  if (ids.IsMD5(digest)) return md5;
  if (ids.IsSHA1(digest)) return sha1;
  if (ids.IsSHA224(digest)) return sha224;
  if (ids.IsSHA256(digest)) return sha256;
  if (ids.IsSHA384(digest)) return sha384;
  if (ids.IsSHA512(digest)) return sha512;
  if (ids.IsSHA512_224(digest)) return sha512_224;
  if (ids.IsSHA512_256(digest)) return sha512_256;
  if (ids.IsRIPEMD160(digest)) return ripemd160;
  if (ids.IsBLAKE2S128(digest)) return blake2s128;
  if (ids.IsBLAKE2S160(digest)) return blake2s160;
  if (ids.IsBLAKE2S224(digest)) return blake2s224;
  if (ids.IsBLAKE2S256(digest)) return blake2s;
  if (ids.IsBLAKE2B128(digest)) return blake2b128;
  if (ids.IsBLAKE2B160(digest)) return blake2b160;
  if (ids.IsBLAKE2B256(digest)) return blake2b256;
  if (ids.IsBLAKE2B384(digest)) return blake2b384;
  if (ids.IsBLAKE2B512(digest)) return blake2b;
  if (ids.IsBLAKE3(digest)) return blake3;
  if (ids.IsSHA3_224(digest)) return sha3_224;
  if (ids.IsSHA3_256(digest)) return sha3_256;
  if (ids.IsSHA3_384(digest)) return sha3_384;
  if (ids.IsSHA3_512(digest)) return sha3_512;
  if (ids.IsKECCAK_224(digest)) return keccak_224;
  if (ids.IsKECCAK_256(digest)) return keccak_256;
  if (ids.IsKECCAK_384(digest)) return keccak_384;
  if (ids.IsKECCAK_512(digest)) return keccak_512;
  if (ids.IsSHAKE128(digest)) return altShake ? shake128Kdf : shake128Digest;
  if (ids.IsSHAKE256(digest)) return altShake ? shake256Kdf : shake256Digest;
  if (ids.IsSHAKE256_114(digest)) return shake256_114;
}

function hashInput(hash, input) {
  if (!input.haveParts) return hash(hexToBytes(input.cleartext));
  const instance = hash.create();
  for (const part of input.parts) instance.update(hexToBytes(part));
  return instance.digest();
}

function OpDigest(input) {
  const hash = hashFor(input.digestType);
  if (!hash) return;
  try {
    return JSON.stringify(bytesToHex(hashInput(hash, input)));
  } catch (error) {
    return;
  }
}

globalThis.CryptofuzzDigest = function (digestType, multipart, buffers) {
  const hash = hashFor(digestType);
  if (!hash || buffers.length === 0) return;
  try {
    const asBytes = (buffer) => ArrayBuffer.isView(buffer)
      ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
      : new Uint8Array(buffer);
    if (multipart === '0') return hash(asBytes(buffers[0]));
    const instance = hash.create();
    for (const buffer of buffers) instance.update(asBytes(buffer));
    return instance.digest();
  } catch (error) {
    return;
  }
};

function OpHMAC(input) {
  const hash = hashFor(input.digestType, true);
  if (!hash) return;
  try {
    const key = hexToBytes(input.cipher.key);
    if (!input.haveParts) {
      return JSON.stringify(bytesToHex(hmac(hash, key, hexToBytes(input.cleartext))));
    }
    const instance = hmac.create(hash, key);
    for (const part of input.parts) instance.update(hexToBytes(part));
    return JSON.stringify(bytesToHex(instance.digest()));
  } catch (error) {
    return;
  }
}

function OpHKDF(input) {
  const hash = hashFor(input.digestType, true);
  if (!hash) return;
  try {
    const result = hkdf(
      hash,
      hexToBytes(input.password),
      hexToBytes(input.salt),
      hexToBytes(input.info),
      Number(input.keySize)
    );
    return JSON.stringify(bytesToHex(result));
  } catch (error) {
    return;
  }
}

function OpPBKDF2(input) {
  const hash = hashFor(input.digestType, true);
  if (!hash) return;
  const iterations = Number(input.iterations);
  if (!Number.isSafeInteger(iterations) || iterations < 1) return;
  try {
    const result = pbkdf2(hash, hexToBytes(input.password), hexToBytes(input.salt), {
      c: iterations,
      dkLen: Number(input.keySize),
    });
    return JSON.stringify(bytesToHex(result));
  } catch (error) {
    return;
  }
}

function toSafeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new RangeError('integer is not safe');
  return number;
}

function OpScrypt(input) {
  try {
    const N = toSafeInteger(input.N);
    const r = toSafeInteger(input.r);
    const p = toSafeInteger(input.p);
    const dkLen = toSafeInteger(input.keySize);
    if (N < 2 || (BigInt(N) & (BigInt(N) - 1n)) !== 0n || r < 1 || p < 1 || p > 4 || dkLen < 1)
      return;
    const result = scrypt(hexToBytes(input.password), hexToBytes(input.salt), {
      N,
      r,
      p,
      dkLen,
    });
    return JSON.stringify(bytesToHex(result));
  } catch (error) {
    return;
  }
}

function OpArgon2(input) {
  try {
    const type = toSafeInteger(input.type);
    const threads = toSafeInteger(input.threads);
    const argon2 = type === 0 ? argon2d : type === 1 ? argon2i : type === 2 ? argon2id : undefined;
    if (!argon2 || threads < 1 || threads > 4) return;
    const result = argon2(hexToBytes(input.password), hexToBytes(input.salt), {
      t: toSafeInteger(input.iterations),
      m: toSafeInteger(input.memory),
      p: threads,
      dkLen: toSafeInteger(input.keySize),
      maxmem: 512 * 1024 * 1024,
    });
    return JSON.stringify(bytesToHex(result));
  } catch (error) {
    return;
  }
}

globalThis.CryptofuzzRun = function (fuzzerInput) {
  const input = JSON.parse(fuzzerInput);
  const operation = input.operation;

  if (ids.IsDigest(operation)) return OpDigest(input);
  if (ids.IsHMAC(operation)) return OpHMAC(input);
  if (ids.IsKDF_HKDF(operation)) return OpHKDF(input);
  if (ids.IsKDF_PBKDF2(operation)) return OpPBKDF2(input);
  if (ids.IsKDF_SCRYPT(operation)) return OpScrypt(input);
  if (ids.IsKDF_ARGON2(operation)) return OpArgon2(input);
};

/* Preserve the standalone bundle interface used by the JS tests and tools. */
if (typeof FuzzerInput !== 'undefined') FuzzerOutput = globalThis.CryptofuzzRun(FuzzerInput);
