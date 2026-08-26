import { createPrivateKey, decapsulate, encapsulate, sign as nativeSign, verify as nativeVerify } from 'node:crypto';
import { createFalcon512, createFalcon1024 } from '@oqs/liboqs-js';
import { packageImporter } from '../package-importer.mjs';

function equalBytes(actual, expected, label, testcase) {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    const error = new Error(`${label} mismatch for ${testcase.operation}/${testcase.algorithm}`);
    error.actual = Buffer.from(actual).toString('hex');
    error.expected = Buffer.from(expected).toString('hex');
    throw error;
  }
}

function assert(value, label, testcase) {
  if (!value) throw new Error(`${label} failed for ${testcase.operation}/${testcase.algorithm}`);
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

function b64(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function nativePrivate(info, keys, seed) {
  if (info.nativeAlg === undefined) return;
  const privateBytes = info.kind === 'kem' || info.family === 'ML-DSA' ? seed : keys.secretKey;
  return createPrivateKey({
    format: 'jwk',
    key: { kty: 'AKP', alg: info.nativeAlg, pub: b64(keys.publicKey), priv: b64(privateBytes) },
  });
}

function fixedRandom(entropy) {
  return (length) => {
    const result = new Uint8Array(length);
    for (let index = 0; index < length; index++) result[index] = entropy[index % entropy.length];
    return result;
  };
}

function signatureOptions(info, testcase, signing) {
  if (info.family === 'Falcon') return signing ? { random: fixedRandom(testcase.entropy) } : {};
  return signing ? { context: testcase.context, extraEntropy: testcase.entropy } : { context: testcase.context };
}

function executeKem(info, testcase) {
  const kem = info.implementation;
  const keys = kem.keygen(testcase.seed);
  equalBytes(kem.getPublicKey(keys.secretKey), keys.publicKey, 'KEM secret/public derivation', testcase);
  const nativeKey = nativePrivate(info, keys, testcase.seed);
  if (testcase.operation === 'KEM_KeyGen') {
    if (nativeKey !== undefined) {
      const exported = nativeKey.export({ format: 'jwk' });
      equalBytes(Buffer.from(exported.pub, 'base64url'), keys.publicKey, 'Node native KEM public key', testcase);
    }
    return keys.publicKey;
  }

  const result = kem.encapsulate(keys.publicKey, testcase.coins);
  equalBytes(kem.decapsulate(result.cipherText, keys.secretKey), result.sharedSecret, 'KEM round-trip', testcase);
  const damaged = Uint8Array.from(result.cipherText);
  damaged[0] ^= 1;
  const rejectedSecret = kem.decapsulate(damaged, keys.secretKey);
  assert(!Buffer.from(rejectedSecret).equals(Buffer.from(result.sharedSecret)), 'modified-ciphertext implicit rejection', testcase);

  if (nativeKey !== undefined) {
    equalBytes(decapsulate(nativeKey, result.cipherText), result.sharedSecret, 'Node native KEM decapsulation oracle', testcase);
    const nativeResult = encapsulate(nativeKey);
    equalBytes(kem.decapsulate(nativeResult.ciphertext, keys.secretKey), nativeResult.sharedKey,
      'Node native KEM encapsulation oracle', testcase);
  }
  return result.cipherText;
}

function executeSignature(info, testcase) {
  const signer = info.implementation;
  const keys = signer.keygen(testcase.seed);
  equalBytes(signer.getPublicKey(keys.secretKey), keys.publicKey, 'signature secret/public derivation', testcase);
  const nativeKey = nativePrivate(info, keys, testcase.seed);
  if (testcase.operation === 'PQSIG_KeyGen') {
    if (nativeKey !== undefined) {
      const exported = nativeKey.export({ format: 'jwk' });
      equalBytes(Buffer.from(exported.pub, 'base64url'), keys.publicKey, 'Node native signature public key', testcase);
    }
    return keys.publicKey;
  }

  const signature = signer.sign(testcase.message, keys.secretKey, signatureOptions(info, testcase, true));
  assert(signer.verify(signature, testcase.message, keys.publicKey, signatureOptions(info, testcase, false)),
    'signature round-trip', testcase);
  const damaged = Uint8Array.from(testcase.message);
  if (damaged.length === 0) {
    assert(!signer.verify(signature, Uint8Array.of(1), keys.publicKey, signatureOptions(info, testcase, false)),
      'modified-message rejection', testcase);
  } else {
    damaged[0] ^= 1;
    assert(!signer.verify(signature, damaged, keys.publicKey, signatureOptions(info, testcase, false)),
      'modified-message rejection', testcase);
  }
  const damagedSignature = Uint8Array.from(signature);
  damagedSignature[bytesIndex(testcase.entropy, damagedSignature.length)] ^= 1;
  let acceptedDamagedSignature = false;
  try {
    acceptedDamagedSignature = signer.verify(
      damagedSignature, testcase.message, keys.publicKey, signatureOptions(info, testcase, false),
    );
  } catch {
    acceptedDamagedSignature = false;
  }
  assert(!acceptedDamagedSignature, 'modified-signature rejection', testcase);

  if (nativeKey !== undefined && testcase.context.length === 0) {
    assert(nativeVerify(null, testcase.message, nativeKey, signature), 'Node native signature verification oracle', testcase);
    const nativeSignature = nativeSign(null, testcase.message, nativeKey);
    assert(signer.verify(nativeSignature, testcase.message, keys.publicKey, { context: testcase.context }),
      'Node native signature generation oracle', testcase);
  }
  if (info.oqs !== undefined) {
    assert(info.oqs.verify(testcase.message, signature, keys.publicKey), 'liboqs WASM Falcon verification oracle', testcase);
    const oqsKeys = info.oqs.generateKeyPair();
    const oqsSignature = info.oqs.sign(testcase.message, oqsKeys.secretKey);
    assert(signer.verify(oqsSignature, testcase.message, oqsKeys.publicKey), 'liboqs WASM Falcon signing oracle', testcase);
  }
  return signature;
}

function materializeRawKem(info, testcase) {
  const kem = info.implementation;
  const raw = { ...testcase, mode: 'raw', matched: true };
  if (testcase.operation === 'KEM_KeyGen') return raw;
  const keys = kem.keygen(testcase.seed);
  if (testcase.operation === 'KEM_Encapsulate') raw.publicKey = Uint8Array.from(keys.publicKey);
  if (testcase.operation === 'KEM_Decapsulate') {
    const result = kem.encapsulate(keys.publicKey, testcase.coins);
    raw.secretKey = Uint8Array.from(keys.secretKey);
    raw.cipherText = Uint8Array.from(result.cipherText);
  }
  return raw;
}

function materializeRawSignature(info, testcase) {
  const signer = info.implementation;
  const raw = { ...testcase, mode: 'raw', matched: true };
  if (testcase.operation === 'PQSIG_KeyGen') return raw;
  const keys = signer.keygen(testcase.seed);
  if (testcase.operation === 'PQSIG_Sign') raw.secretKey = Uint8Array.from(keys.secretKey);
  if (testcase.operation === 'PQSIG_Verify') {
    raw.publicKey = Uint8Array.from(keys.publicKey);
    raw.signature = Uint8Array.from(signer.sign(
      testcase.message, keys.secretKey, signatureOptions(info, testcase, true),
    ));
  }
  return raw;
}

function executeRawKem(info, testcase) {
  const kem = info.implementation;
  if (testcase.operation === 'KEM_KeyGen') {
    const keys = attempt(() => kem.keygen(testcase.seed));
    if (!keys.accepted) return rawOutcome(false);
    assert(keys.value?.publicKey instanceof Uint8Array && keys.value?.secretKey instanceof Uint8Array,
      'raw KEM keygen output shape', testcase);
    equalBytes(kem.getPublicKey(keys.value.secretKey), keys.value.publicKey, 'raw KEM secret/public derivation', testcase);
    return rawOutcome(true, keys.value.publicKey);
  }
  if (testcase.operation === 'KEM_Encapsulate') {
    const first = attempt(() => kem.encapsulate(testcase.publicKey, testcase.coins));
    if (!first.accepted) return rawOutcome(false);
    assert(first.value?.cipherText instanceof Uint8Array && first.value?.sharedSecret instanceof Uint8Array,
      'raw KEM encapsulation output shape', testcase);
    const second = kem.encapsulate(testcase.publicKey, testcase.coins);
    equalBytes(second.cipherText, first.value.cipherText, 'raw KEM deterministic ciphertext', testcase);
    equalBytes(second.sharedSecret, first.value.sharedSecret, 'raw KEM deterministic shared secret', testcase);
    return rawOutcome(true, first.value.cipherText);
  }
  const first = attempt(() => kem.decapsulate(testcase.cipherText, testcase.secretKey));
  if (!first.accepted) return rawOutcome(false);
  assert(first.value instanceof Uint8Array, 'raw KEM decapsulation output shape', testcase);
  equalBytes(kem.decapsulate(testcase.cipherText, testcase.secretKey), first.value,
    'raw KEM deterministic decapsulation', testcase);
  return rawOutcome(true, first.value);
}

function executeRawSignature(info, testcase) {
  const signer = info.implementation;
  if (testcase.operation === 'PQSIG_KeyGen') {
    const keys = attempt(() => signer.keygen(testcase.seed));
    if (!keys.accepted) return rawOutcome(false);
    assert(keys.value?.publicKey instanceof Uint8Array && keys.value?.secretKey instanceof Uint8Array,
      'raw signature keygen output shape', testcase);
    equalBytes(signer.getPublicKey(keys.value.secretKey), keys.value.publicKey,
      'raw signature secret/public derivation', testcase);
    return rawOutcome(true, keys.value.publicKey);
  }
  if (testcase.operation === 'PQSIG_Sign') {
    const signed = attempt(() => signer.sign(
      testcase.message, testcase.secretKey, signatureOptions(info, testcase, true),
    ));
    if (!signed.accepted) return rawOutcome(false);
    assert(signed.value instanceof Uint8Array, 'raw signature output shape', testcase);
    if (testcase.matched === true) {
      const publicKey = signer.getPublicKey(testcase.secretKey);
      assert(signer.verify(signed.value, testcase.message, publicKey, signatureOptions(info, testcase, false)),
        'raw secret-key signature verification', testcase);
    }
    return rawOutcome(true, signed.value);
  }
  const verified = attempt(() => signer.verify(
    testcase.signature, testcase.message, testcase.publicKey, signatureOptions(info, testcase, false),
  ));
  if (!verified.accepted) return rawOutcome(false);
  assert(typeof verified.value === 'boolean', 'raw signature verification result type', testcase);
  return rawOutcome(verified.value);
}

function bytesIndex(bytes, limit) {
  let value = 0;
  for (let index = 0; index < Math.min(4, bytes.length); index++) value = (value * 256 + bytes[index]) >>> 0;
  return value % limit;
}

export async function createPostQuantumTarget(sourceDirectory) {
  const load = await packageImporter('@noble/post-quantum', sourceDirectory);
  const [mlKem, hybrid, mlDsa, slhDsa, falcon, oqs512, oqs1024] = await Promise.all([
    load('ml-kem.js'), load('hybrid.js'), load('ml-dsa.js'), load('slh-dsa.js'), load('falcon.js'),
    createFalcon512(), createFalcon1024(),
  ]);
  const kemDefinitions = [
    ['ML_KEM_512', mlKem.ml_kem512, 'ML-KEM-512'],
    ['ML_KEM_768', mlKem.ml_kem768, 'ML-KEM-768'],
    ['ML_KEM_1024', mlKem.ml_kem1024, 'ML-KEM-1024'],
    ['ML_KEM_768_X25519', hybrid.ml_kem768_x25519],
    ['ML_KEM_768_P256', hybrid.ml_kem768_p256],
    ['ML_KEM_1024_P384', hybrid.ml_kem1024_p384],
    ['KitchenSink_ML_KEM_768_X25519', hybrid.KitchenSink_ml_kem768_x25519],
    ['QSF_ML_KEM_768_P256', hybrid.QSF_ml_kem768_p256],
    ['QSF_ML_KEM_1024_P384', hybrid.QSF_ml_kem1024_p384],
    ['X_Wing', hybrid.ml_kem768_x25519],
  ];
  const slhNames = ['sha2_128f', 'sha2_128s', 'sha2_192f', 'sha2_192s', 'sha2_256f', 'sha2_256s',
    'shake_128f', 'shake_128s', 'shake_192f', 'shake_192s', 'shake_256f', 'shake_256s'];
  const signatureDefinitions = [
    ['ML_DSA_44', mlDsa.ml_dsa44, 'ML-DSA-44', 'ML-DSA'],
    ['ML_DSA_65', mlDsa.ml_dsa65, 'ML-DSA-65', 'ML-DSA'],
    ['ML_DSA_87', mlDsa.ml_dsa87, 'ML-DSA-87', 'ML-DSA'],
    ...slhNames.map((suffix) => [
      `SLH_DSA_${suffix.split('_')[0].toUpperCase()}_${suffix.split('_')[1]}`, slhDsa[`slh_dsa_${suffix}`],
      `SLH-DSA-${suffix.startsWith('sha2') ? 'SHA2' : 'SHAKE'}-${suffix.split('_')[1]}`, 'SLH-DSA',
    ]),
    ['Falcon_512', falcon.falcon512, undefined, 'Falcon', oqs512],
    ['Falcon_1024', falcon.falcon1024, undefined, 'Falcon', oqs1024],
  ];
  const algorithms = new Map();
  for (const [name, implementation, nativeAlg] of kemDefinitions) {
    algorithms.set(name, { name, implementation, nativeAlg, kind: 'kem', family: name.startsWith('ML_KEM_') && !name.includes('X') && !name.includes('P') ? 'ML-KEM' : 'Hybrid' });
  }
  for (const [name, implementation, nativeAlg, family, oqs] of signatureDefinitions) {
    algorithms.set(name, { name, implementation, nativeAlg, family, oqs, kind: 'signature' });
  }
  const descriptors = [...algorithms.values()].map(({ name, implementation, family, kind }) => ({
    name, family, kind, lengths: implementation.lengths,
  }));
  return {
    algorithms,
    descriptors,
    materializeRaw(testcase) {
      const info = algorithms.get(testcase.algorithm);
      return info.kind === 'kem' ? materializeRawKem(info, testcase) : materializeRawSignature(info, testcase);
    },
    execute(testcase) {
      const info = algorithms.get(testcase.algorithm);
      if (testcase.mode === 'raw') {
        return info.kind === 'kem' ? executeRawKem(info, testcase) : executeRawSignature(info, testcase);
      }
      return info.kind === 'kem' ? executeKem(info, testcase) : executeSignature(info, testcase);
    },
  };
}
