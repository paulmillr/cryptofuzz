import { createCipheriv, createDecipheriv } from 'node:crypto';
import { AES } from '@stablelib/aes';
import { SIV } from '@stablelib/siv';
import sodium from 'libsodium-wrappers-sumo';
import { packageImporter } from '../package-importer.mjs';

const AES_KW_IV = Uint8Array.from([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);
const AES_KWP_IV = Uint8Array.from([0xa6, 0x59, 0x59, 0xa6]);

function aesSpecs(kind, suffix, extra = {}) {
  return [128, 192, 256].map((bits) => ({
    name: `AES_${bits}_${suffix}`,
    kind,
    keyLength: bits / 8,
    ...extra,
  }));
}

export const CIPHER_SPECS = Object.freeze([
  ...aesSpecs('ecb', 'ECB', { ivLength: 0 }),
  ...aesSpecs('cbc', 'CBC', { ivLength: 16 }),
  ...aesSpecs('ctr', 'CTR', { ivLength: 16 }),
  ...aesSpecs('cfb', 'CFB', { ivLength: 16 }),
  ...aesSpecs('cfb', 'CFB128', { ivLength: 16 }),
  ...aesSpecs('gcm', 'GCM', { ivLengths: Array.from({ length: 25 }, (_, index) => 8 + index), aead: true }),
  { name: 'AES_128_GCM_SIV', kind: 'gcmsiv', keyLength: 16, ivLength: 12, aead: true, selfTested: true },
  { name: 'AES_256_GCM_SIV', kind: 'gcmsiv', keyLength: 32, ivLength: 12, aead: true, selfTested: true },
  ...aesSpecs('aessiv', 'SIV_CMAC', { keyScale: 2, ivLengths: [0, 1, 8, 12, 16, 24, 32], aead: true, tagAtStart: true }),
  ...aesSpecs('aeskw', 'WRAP', { ivLength: 0 }),
  ...aesSpecs('aeskwp', 'WRAP_PAD', { ivLength: 0 }),
  { name: 'CHACHA20', kind: 'chacha20', keyLength: 32, ivLength: 12, stream: true },
  { name: 'CHACHA20_POLY1305', kind: 'chacha20poly1305', keyLength: 32, ivLength: 12, aead: true },
  { name: 'XCHACHA20_POLY1305', kind: 'xchacha20poly1305', keyLength: 32, ivLength: 24, aead: true },
  { name: 'SALSA20_128', kind: 'salsa20', keyLength: 16, ivLength: 8, stream: true, selfTested: true },
  { name: 'SALSA20_256', kind: 'salsa20', keyLength: 32, ivLength: 8, stream: true },
].map((spec) => ({ ...spec, keyLength: spec.keyLength * (spec.keyScale ?? 1) })));

const SPECS_BY_NAME = new Map(CIPHER_SPECS.map((spec) => [spec.name, spec]));

function equal(actual, expected, label, testcase) {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    const error = new Error(`${label} mismatch for Cipher/${testcase.cipher}`);
    error.actual = Buffer.from(actual).toString('hex');
    error.expected = Buffer.from(expected).toString('hex');
    throw error;
  }
}

function outcome(run) {
  try {
    const value = run();
    return value === null ? { ok: false } : { ok: true, value };
  } catch {
    return { ok: false };
  }
}

function equalOutcome(actual, expected, label, testcase) {
  if (actual.ok !== expected.ok) {
    const error = new Error(`${label} acceptance mismatch for ${testcase.operation}/${testcase.cipher}`);
    error.actual = actual.ok ? 'accepted' : 'rejected';
    error.expected = expected.ok ? 'accepted' : 'rejected';
    throw error;
  }
  if (actual.ok) equal(actual.value, expected.value, label, testcase);
}

function nobleCipher(functions, spec, testcase) {
  const { key, iv, aad } = testcase;
  if (spec.kind === 'ecb') return functions.ecb(key, { disablePadding: true });
  if (spec.kind === 'cbc') return functions.cbc(key, iv);
  if (spec.kind === 'ctr') return functions.ctr(key, iv);
  if (spec.kind === 'cfb') return functions.cfb(key, iv);
  if (spec.kind === 'gcm') return functions.gcm(key, iv, aad);
  if (spec.kind === 'gcmsiv') return functions.gcmsiv(key, iv, aad);
  if (spec.kind === 'aessiv') {
    const associated = [aad];
    if (iv.length > 0) associated.push(iv);
    return functions.aessiv(key, ...associated);
  }
  if (spec.kind === 'aeskw') return functions.aeskw(key);
  if (spec.kind === 'aeskwp') return functions.aeskwp(key);
  if (spec.kind === 'chacha20poly1305') return functions.chacha20poly1305(key, iv, aad);
  if (spec.kind === 'xchacha20poly1305') return functions.xchacha20poly1305(key, iv, aad);
  throw new Error(`no noble cipher for ${spec.kind}`);
}

function nobleEncrypt(functions, spec, testcase) {
  if (spec.kind === 'chacha20') return functions.chacha20(testcase.key, testcase.iv, testcase.data);
  if (spec.kind === 'salsa20') return functions.salsa20(testcase.key, testcase.iv, testcase.data);
  return nobleCipher(functions, spec, testcase).encrypt(testcase.data);
}

function nobleDecrypt(functions, spec, testcase, sealed) {
  if (spec.stream) {
    if (spec.kind === 'chacha20') return functions.chacha20(testcase.key, testcase.iv, sealed);
    return functions.salsa20(testcase.key, testcase.iv, sealed);
  }
  return nobleCipher(functions, spec, testcase).decrypt(sealed);
}

function nodeName(spec) {
  const bits = spec.keyLength * 8;
  if (['ecb', 'cbc', 'ctr', 'cfb', 'gcm'].includes(spec.kind)) return `aes-${bits}-${spec.kind}`;
  if (spec.kind === 'aeskw') return `id-aes${bits}-wrap`;
  if (spec.kind === 'aeskwp') return `id-aes${bits}-wrap-pad`;
  if (spec.kind === 'chacha20') return 'chacha20';
  if (spec.kind === 'chacha20poly1305') return 'chacha20-poly1305';
  return undefined;
}

function nodeIv(spec, testcase) {
  if (spec.kind === 'ecb') return null;
  if (spec.kind === 'aeskw') return AES_KW_IV;
  if (spec.kind === 'aeskwp') return AES_KWP_IV;
  if (spec.kind === 'chacha20') {
    const iv = new Uint8Array(16);
    iv.set(testcase.iv, 4);
    return iv;
  }
  return testcase.iv;
}

function nodeEncrypt(spec, testcase) {
  const name = nodeName(spec);
  if (name === undefined) return undefined;
  const options = spec.kind === 'chacha20poly1305' ? { authTagLength: 16 } : undefined;
  const cipher = createCipheriv(name, testcase.key, nodeIv(spec, testcase), options);
  if (spec.kind === 'ecb') cipher.setAutoPadding(false);
  if (spec.aead) cipher.setAAD(testcase.aad);
  const body = Buffer.concat([cipher.update(testcase.data), cipher.final()]);
  if (!spec.aead) return Uint8Array.from(body);
  return Uint8Array.from(Buffer.concat([body, cipher.getAuthTag()]));
}

function nodeDecrypt(spec, testcase, sealed) {
  const name = nodeName(spec);
  if (name === undefined) return undefined;
  const options = spec.kind === 'chacha20poly1305' ? { authTagLength: 16 } : undefined;
  const decipher = createDecipheriv(name, testcase.key, nodeIv(spec, testcase), options);
  if (spec.kind === 'ecb') decipher.setAutoPadding(false);
  let body = sealed;
  if (spec.aead) {
    body = sealed.subarray(0, sealed.length - 16);
    decipher.setAAD(testcase.aad);
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  }
  return Uint8Array.from(Buffer.concat([decipher.update(body), decipher.final()]));
}

function requireSodiumWasm() {
  const wasmExport = sodium.libsodium?._crypto_stream_salsa20_xor;
  if (typeof wasmExport !== 'function' || !Function.prototype.toString.call(wasmExport).includes('[native code]')) {
    throw new Error('libsodium WebAssembly backend is unavailable');
  }
}

function sodiumSalsa20Xor(key, nonce, message) {
  const raw = sodium.libsodium;
  const bufferLength = Math.max(1, message.length);
  const allocationLength = bufferLength * 2 + nonce.length + key.length;
  const allocation = raw._malloc(allocationLength);
  if (allocation === 0) throw new Error('libsodium allocation failed');
  try {
    const outputPointer = allocation;
    const messagePointer = outputPointer + bufferLength;
    const noncePointer = messagePointer + bufferLength;
    const keyPointer = noncePointer + nonce.length;
    raw.HEAPU8.set(message, messagePointer);
    raw.HEAPU8.set(nonce, noncePointer);
    raw.HEAPU8.set(key, keyPointer);
    // Emscripten legalizes the uint64_t message length as low/high uint32_t arguments.
    const status = raw._crypto_stream_salsa20_xor(
      outputPointer, messagePointer, message.length, 0, noncePointer, keyPointer,
    );
    if (status !== 0) throw new Error('libsodium Salsa20 failed');
    return Uint8Array.from(raw.HEAPU8.subarray(outputPointer, outputPointer + message.length));
  } finally {
    raw.HEAPU8.fill(0, allocation, allocation + allocationLength);
    raw._free(allocation);
  }
}

function externalEncrypt(spec, testcase) {
  if (spec.kind === 'salsa20' && spec.keyLength === 32) {
    return sodiumSalsa20Xor(testcase.key, testcase.iv, testcase.data);
  }
  if (spec.kind === 'xchacha20poly1305') {
    return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      testcase.data, testcase.aad, null, testcase.iv, testcase.key,
    );
  }
  if (spec.kind === 'aessiv') {
    const associated = [testcase.aad];
    if (testcase.iv.length > 0) associated.push(testcase.iv);
    const cipher = new SIV(AES, testcase.key);
    const result = cipher.seal(associated, testcase.data);
    cipher.clean();
    return result;
  }
  return undefined;
}

function externalDecrypt(spec, testcase, sealed) {
  if (spec.kind === 'salsa20' && spec.keyLength === 32) {
    return sodiumSalsa20Xor(testcase.key, testcase.iv, sealed);
  }
  if (spec.kind === 'xchacha20poly1305') {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, sealed, testcase.aad, testcase.iv, testcase.key,
    );
  }
  if (spec.kind === 'aessiv') {
    const associated = [testcase.aad];
    if (testcase.iv.length > 0) associated.push(testcase.iv);
    const cipher = new SIV(AES, testcase.key);
    const result = cipher.open(associated, sealed);
    cipher.clean();
    return result;
  }
  return undefined;
}

function hasExternalOracle(spec) {
  return (spec.kind === 'salsa20' && spec.keyLength === 32) ||
    spec.kind === 'xchacha20poly1305' || spec.kind === 'aessiv';
}

function externalOracleLabel(spec) {
  return spec.kind === 'aessiv' ? 'StableLib AES-SIV oracle' : 'libsodium WASM oracle';
}

function interoperableShape(spec, testcase) {
  if (testcase.key.length !== spec.keyLength) return false;
  if (spec.ivLengths !== undefined ? !spec.ivLengths.includes(testcase.iv.length) : testcase.iv.length !== spec.ivLength) {
    return false;
  }
  if (!spec.aead && testcase.aad.length !== 0) return false;
  if (spec.kind === 'ecb' && testcase.data.length % 16 !== 0) return false;
  if (spec.kind === 'cbc' && testcase.operation === 'SymmetricDecrypt' &&
      (testcase.data.length === 0 || testcase.data.length % 16 !== 0)) return false;
  const kwMinimum = testcase.operation === 'SymmetricDecrypt' ? 24 : 16;
  if (spec.kind === 'aeskw' && (testcase.data.length < kwMinimum || testcase.data.length % 8 !== 0)) return false;
  if (spec.kind === 'aeskwp' && (testcase.operation === 'SymmetricEncrypt'
    ? testcase.data.length === 0 : testcase.data.length < 16 || testcase.data.length % 8 !== 0)) return false;
  if (spec.aead && testcase.operation === 'SymmetricDecrypt' && testcase.data.length < 16) return false;
  return true;
}

function executeRaw(functions, spec, testcase) {
  const encrypting = testcase.operation === 'SymmetricEncrypt';
  const actual = outcome(() => encrypting
    ? nobleEncrypt(functions, spec, testcase)
    : nobleDecrypt(functions, spec, testcase, testcase.data));
  const hasNodeOracle = nodeName(spec) !== undefined;
  // Noble's AES entry points intentionally select AES-128/192/256 from the
  // supplied key length, while the Cryptofuzz identifier fixes one variant.
  // A differently sized raw key is still useful parser input, but is not an
  // interoperable testcase for that fixed external algorithm name.
  const interoperable = interoperableShape(spec, testcase);
  if (interoperable && (hasNodeOracle || hasExternalOracle(spec))) {
    const oracle = hasNodeOracle
      ? outcome(() => encrypting ? nodeEncrypt(spec, testcase) : nodeDecrypt(spec, testcase, testcase.data))
      : outcome(() => encrypting ? externalEncrypt(spec, testcase) : externalDecrypt(spec, testcase, testcase.data));
    const label = hasNodeOracle ? 'raw Node/OpenSSL oracle' : `raw ${externalOracleLabel(spec)}`;
    equalOutcome(actual, oracle, label, testcase);
  }
  return { outcome: actual.ok ? 'accept' : 'reject', value: actual.value };
}

function selfTest(functions) {
  const gcm = {
    version: 1,
    operation: 'Cipher',
    cipher: 'AES_128_GCM',
    key: new Uint8Array(16),
    iv: new Uint8Array(12),
    aad: new Uint8Array(),
    data: new Uint8Array(),
  };
  equal(nobleEncrypt(functions, SPECS_BY_NAME.get(gcm.cipher), gcm),
    Buffer.from('58e2fccefa7e3061367f1d57a4e7455a', 'hex'), 'NIST GCM known-answer', gcm);

  const gcmSiv = {
    version: 1,
    operation: 'Cipher',
    cipher: 'AES_128_GCM_SIV',
    key: Uint8Array.from(Buffer.from('01000000000000000000000000000000', 'hex')),
    iv: Uint8Array.from(Buffer.from('030000000000000000000000', 'hex')),
    aad: new Uint8Array(),
    data: new Uint8Array(),
  };
  equal(nobleEncrypt(functions, SPECS_BY_NAME.get(gcmSiv.cipher), gcmSiv),
    Buffer.from('dc20e2d83f25705bb49e439eca56de25', 'hex'), 'RFC 8452 known-answer', gcmSiv);

  const gcmSivPayload = { ...gcmSiv, data: Uint8Array.from(Buffer.from('0100000000000000', 'hex')) };
  equal(nobleEncrypt(functions, SPECS_BY_NAME.get(gcmSivPayload.cipher), gcmSivPayload),
    Buffer.from('b5d839330ac7b786578782fff6013b815b287c22493a364c', 'hex'),
    'RFC 8452 payload known-answer', gcmSivPayload);

  const siv = {
    version: 1,
    operation: 'Cipher',
    cipher: 'AES_128_SIV_CMAC',
    key: Uint8Array.from(Buffer.from('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex')),
    iv: new Uint8Array(),
    aad: Uint8Array.from(Buffer.from('101112131415161718191a1b1c1d1e1f2021222324252627', 'hex')),
    data: Uint8Array.from(Buffer.from('112233445566778899aabbccddee', 'hex')),
  };
  equal(nobleEncrypt(functions, SPECS_BY_NAME.get(siv.cipher), siv),
    Buffer.from('85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c', 'hex'),
    'RFC 5297 known-answer', siv);

  // RFC 5649 requires every recovered KWP pad octet to be zero. Build the n=1
  // AES codebook input directly so the AIV/MLI remain valid while one pad byte is not.
  const kwpKey = new Uint8Array(16);
  const malformedKwpBlock = Buffer.from('a65959a6000000014200000000000001', 'hex');
  const kwpCipher = createCipheriv('aes-128-ecb', kwpKey, null);
  kwpCipher.setAutoPadding(false);
  const malformedKwp = Buffer.concat([kwpCipher.update(malformedKwpBlock), kwpCipher.final()]);
  if (outcome(() => functions.aeskwp(kwpKey).decrypt(malformedKwp)).ok) {
    throw new Error('AES-KWP accepted nonzero recovered padding');
  }

  const salsa = {
    version: 1,
    operation: 'Cipher',
    cipher: 'SALSA20_128',
    key: Uint8Array.of(0x80, ...new Uint8Array(15)),
    iv: new Uint8Array(8),
    aad: new Uint8Array(),
    data: new Uint8Array(64),
  };
  equal(nobleEncrypt(functions, SPECS_BY_NAME.get(salsa.cipher), salsa), Buffer.from(
    '4dfa5e481da23ea09a31022050859936da52fcee218005164f267cb65f5cfd7f' +
    '2b4f97e0ff16924a52df269515110a07f9e460bc65ef95da58f740b7d1dbb0aa', 'hex'),
  'eSTREAM Salsa20/20 known-answer', salsa);

  const salsa256 = { ...salsa, cipher: 'SALSA20_256', key: Uint8Array.of(0x80, ...new Uint8Array(31)) };
  const salsa256Sealed = nobleEncrypt(functions, SPECS_BY_NAME.get(salsa256.cipher), salsa256);
  equal(salsa256Sealed, externalEncrypt(SPECS_BY_NAME.get(salsa256.cipher), salsa256),
    'libsodium WASM oracle', salsa256);
  equal(salsa256Sealed, Buffer.from(
    'e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844' +
    'b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117', 'hex'),
  'eSTREAM Salsa20/20 known-answer', salsa256);

  const xchacha = {
    version: 1,
    operation: 'Cipher',
    cipher: 'XCHACHA20_POLY1305',
    key: Uint8Array.from({ length: 32 }, (_, index) => index),
    iv: Uint8Array.from({ length: 24 }, (_, index) => index + 32),
    aad: Uint8Array.of(1, 3, 3, 7),
    data: Uint8Array.from({ length: 65 }, (_, index) => index * 5 & 0xff),
  };
  const xchachaSpec = SPECS_BY_NAME.get(xchacha.cipher);
  const xchachaSealed = nobleEncrypt(functions, xchachaSpec, xchacha);
  equal(xchachaSealed, externalEncrypt(xchachaSpec, xchacha), 'libsodium WASM oracle', xchacha);
  equal(externalDecrypt(xchachaSpec, xchacha, xchachaSealed), xchacha.data,
    'libsodium WASM decrypt', xchacha);

  const xsalsa = {
    version: 1,
    operation: 'Cipher',
    cipher: 'XSALSA20_POLY1305',
    key: Uint8Array.from(Buffer.from('givKPH4F/eDcIEUZcws1+BIWqcnx35Ul4qkA7Ilxj1c=', 'base64')),
    iv: Uint8Array.from(Buffer.from('crkCCNKADjatFscwlBoDjXw62dhwMNMp', 'base64')),
    aad: new Uint8Array(),
    data: new Uint8Array(),
  };
  const xsalsaSealed = functions.xsalsa20poly1305(xsalsa.key, xsalsa.iv).encrypt(xsalsa.data);
  equal(xsalsaSealed, sodium.crypto_secretbox_easy(xsalsa.data, xsalsa.iv, xsalsa.key),
    'libsodium WASM oracle', xsalsa);
  equal(xsalsaSealed, Buffer.from('ebNFUe0iT6F8tkYMy5Cg2Q==', 'base64'), 'TweetNaCl secretbox known-answer', xsalsa);
  const damaged = Uint8Array.from(xsalsaSealed);
  damaged[damaged.length - 1] ^= 1;
  if (outcome(() => functions.xsalsa20poly1305(xsalsa.key, xsalsa.iv).decrypt(damaged)).ok) {
    throw new Error('TweetNaCl secretbox accepted modified tag');
  }
  if (outcome(() => sodium.crypto_secretbox_open_easy(damaged, xsalsa.iv, xsalsa.key)).ok) {
    throw new Error('libsodium secretbox accepted modified tag');
  }
}

export async function createCiphersTarget(sourceDirectory) {
  await sodium.ready;
  requireSodiumWasm();
  const load = await packageImporter('@noble/ciphers', sourceDirectory);
  const [aes, chacha, salsa] = await Promise.all([load('aes.js'), load('chacha.js'), load('salsa.js')]);
  const functions = { ...aes, ...chacha, ...salsa };
  selfTest(functions);
  return {
    specs: CIPHER_SPECS,
    spec(name) {
      return SPECS_BY_NAME.get(name);
    },
    execute(testcase) {
      const spec = SPECS_BY_NAME.get(testcase.cipher);
      if (testcase.mode === 'raw') return executeRaw(functions, spec, testcase);
      if (testcase.operation === 'SymmetricDecrypt') {
        const actual = outcome(() => nobleDecrypt(functions, spec, testcase, testcase.data));
        const hasNodeOracle = nodeName(spec) !== undefined;
        if (hasNodeOracle || hasExternalOracle(spec)) {
          const oracle = hasNodeOracle
            ? outcome(() => nodeDecrypt(spec, testcase, testcase.data))
            : outcome(() => externalDecrypt(spec, testcase, testcase.data));
          equalOutcome(actual, oracle,
            hasNodeOracle ? 'Node/OpenSSL decrypt oracle' : `${externalOracleLabel(spec)} decrypt`, testcase);
        }
        return actual.ok ? actual.value : new Uint8Array();
      }
      const sealed = nobleEncrypt(functions, spec, testcase);
      equal(nobleDecrypt(functions, spec, testcase, sealed), testcase.data, 'Noble encrypt/decrypt', testcase);
      const oracle = nodeEncrypt(spec, testcase) ?? externalEncrypt(spec, testcase);
      if (oracle !== undefined) {
        equal(sealed, oracle, nodeName(spec) === undefined ? externalOracleLabel(spec) : 'Node/OpenSSL oracle', testcase);
        const opened = nodeName(spec) === undefined
          ? externalDecrypt(spec, testcase, oracle)
          : nodeDecrypt(spec, testcase, oracle);
        if (opened !== undefined) {
          equal(opened, testcase.data,
            nodeName(spec) === undefined ? `${externalOracleLabel(spec)} decrypt` : 'Node/OpenSSL decrypt oracle', testcase);
        }
      }
      if (spec.aead) {
        const damaged = Uint8Array.from(sealed);
        damaged[damaged.length - 1] ^= 1;
        if (outcome(() => nobleDecrypt(functions, spec, testcase, damaged)).ok) {
          throw new Error(`Noble accepted modified authenticated ciphertext for ${testcase.cipher}`);
        }
        if (nodeName(spec) !== undefined || hasExternalOracle(spec)) {
          const independent = nodeName(spec) !== undefined
            ? outcome(() => nodeDecrypt(spec, testcase, damaged))
            : outcome(() => externalDecrypt(spec, testcase, damaged));
          if (independent.ok) throw new Error(`independent oracle accepted modified authenticated ciphertext for ${testcase.cipher}`);
        }
      }
      return sealed;
    },
  };
}
