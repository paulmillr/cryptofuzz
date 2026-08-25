import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { falcon512, falcon1024 } from '@noble/post-quantum/falcon.js';
import {
  KitchenSink_ml_kem768_x25519,
  QSF_ml_kem768_p256,
  QSF_ml_kem1024_p384,
  ml_kem768_x25519,
  ml_kem768_p256,
  ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as ids from './ids.js';

function kemFor(type) {
  const id = BigInt(type);
  if (ids.IsML_KEM_512(id)) return ml_kem512;
  if (ids.IsML_KEM_768(id)) return ml_kem768;
  if (ids.IsML_KEM_1024(id)) return ml_kem1024;
  if (ids.IsML_KEM_768_X25519(id)) return ml_kem768_x25519;
  if (ids.IsML_KEM_768_P256(id)) return ml_kem768_p256;
  if (ids.IsML_KEM_1024_P384(id)) return ml_kem1024_p384;
  if (ids.IsKitchenSink_ML_KEM_768_X25519(id)) return KitchenSink_ml_kem768_x25519;
  if (ids.IsQSF_ML_KEM_768_P256(id)) return QSF_ml_kem768_p256;
  if (ids.IsQSF_ML_KEM_1024_P384(id)) return QSF_ml_kem1024_p384;
  // Noble documents this CG hybrid preset as the X-Wing construction.
  if (ids.IsX_Wing(id)) return ml_kem768_x25519;
}

function signerFor(type) {
  const id = BigInt(type);
  if (ids.IsML_DSA_44(id)) return ml_dsa44;
  if (ids.IsML_DSA_65(id)) return ml_dsa65;
  if (ids.IsML_DSA_87(id)) return ml_dsa87;
  if (ids.IsSLH_DSA_SHA2_128f(id)) return slh_dsa_sha2_128f;
  if (ids.IsSLH_DSA_SHA2_128s(id)) return slh_dsa_sha2_128s;
  if (ids.IsSLH_DSA_SHA2_192f(id)) return slh_dsa_sha2_192f;
  if (ids.IsSLH_DSA_SHA2_192s(id)) return slh_dsa_sha2_192s;
  if (ids.IsSLH_DSA_SHA2_256f(id)) return slh_dsa_sha2_256f;
  if (ids.IsSLH_DSA_SHA2_256s(id)) return slh_dsa_sha2_256s;
  if (ids.IsSLH_DSA_SHAKE_128f(id)) return slh_dsa_shake_128f;
  if (ids.IsSLH_DSA_SHAKE_128s(id)) return slh_dsa_shake_128s;
  if (ids.IsSLH_DSA_SHAKE_192f(id)) return slh_dsa_shake_192f;
  if (ids.IsSLH_DSA_SHAKE_192s(id)) return slh_dsa_shake_192s;
  if (ids.IsSLH_DSA_SHAKE_256f(id)) return slh_dsa_shake_256f;
  if (ids.IsSLH_DSA_SHAKE_256s(id)) return slh_dsa_shake_256s;
  if (ids.IsFalcon_512(id)) return falcon512;
  if (ids.IsFalcon_1024(id)) return falcon1024;
}

function decodeExact(hex, length) {
  const value = hexToBytes(hex);
  if (!Number.isSafeInteger(length) || value.length !== length) throw new Error('wrong length');
  return value;
}

function OpKEMKeyGen(input) {
  const kem = kemFor(input.kemType);
  if (!kem || kem.lengths.seed === undefined) return;
  try {
    const result = kem.keygen(decodeExact(input.seed, kem.lengths.seed));
    return JSON.stringify({
      publicKey: bytesToHex(result.publicKey),
      secretKey: bytesToHex(result.secretKey),
    });
  } catch (error) {
    return;
  }
}

function OpKEMEncapsulate(input) {
  const kem = kemFor(input.kemType);
  const coinsLength = kem?.lengths.msgRand ?? kem?.lengths.msg;
  if (!kem || coinsLength === undefined) return;
  try {
    const result = kem.encapsulate(
      decodeExact(input.publicKey, kem.lengths.publicKey),
      decodeExact(input.coins, coinsLength)
    );
    return JSON.stringify({
      ciphertext: bytesToHex(result.cipherText),
      sharedSecret: bytesToHex(result.sharedSecret),
    });
  } catch (error) {
    return;
  }
}

function OpKEMDecapsulate(input) {
  const kem = kemFor(input.kemType);
  if (!kem) return;
  try {
    const result = kem.decapsulate(
      decodeExact(input.ciphertext, kem.lengths.cipherText),
      decodeExact(input.secretKey, kem.lengths.secretKey)
    );
    return JSON.stringify(bytesToHex(result));
  } catch (error) {
    return;
  }
}

function OpPQSIGKeyGen(input) {
  const signer = signerFor(input.pqSignatureType);
  if (!signer || signer.lengths.seed === undefined) return;
  try {
    const result = signer.keygen(decodeExact(input.seed, signer.lengths.seed));
    return JSON.stringify({
      publicKey: bytesToHex(result.publicKey),
      secretKey: bytesToHex(result.secretKey),
    });
  } catch (error) {
    return;
  }
}

function signatureOptions(signer, input, signing) {
  const context = hexToBytes(input.context);
  const isFalcon = signer === falcon512 || signer === falcon1024;
  if (isFalcon && context.length !== 0) throw new Error('Falcon has no context');
  const options = isFalcon ? {} : { context };
  if (!signing) return options;
  const extraEntropy = hexToBytes(input.extraEntropy);
  if (extraEntropy.length === 0) {
    options.extraEntropy = false;
  } else {
    options.extraEntropy = decodeExact(input.extraEntropy, signer.lengths.signRand);
  }
  return options;
}

function OpPQSIGSign(input) {
  const signer = signerFor(input.pqSignatureType);
  if (!signer) return;
  try {
    const signature = signer.sign(
      hexToBytes(input.message),
      decodeExact(input.secretKey, signer.lengths.secretKey),
      signatureOptions(signer, input, true)
    );
    return JSON.stringify(bytesToHex(signature));
  } catch (error) {
    return;
  }
}

function OpPQSIGVerify(input) {
  const signer = signerFor(input.pqSignatureType);
  if (!signer) return;
  let verified = false;
  try {
    verified = signer.verify(
      hexToBytes(input.signature),
      hexToBytes(input.message),
      decodeExact(input.publicKey, signer.lengths.publicKey),
      signatureOptions(signer, input, false)
    );
  } catch (error) {
    verified = false;
  }
  return JSON.stringify(verified);
}

const input = JSON.parse(FuzzerInput);
const operation = BigInt(input.operation);

if (ids.IsKEM_KeyGen(operation)) FuzzerOutput = OpKEMKeyGen(input);
else if (ids.IsKEM_Encapsulate(operation)) FuzzerOutput = OpKEMEncapsulate(input);
else if (ids.IsKEM_Decapsulate(operation)) FuzzerOutput = OpKEMDecapsulate(input);
else if (ids.IsPQSIG_KeyGen(operation)) FuzzerOutput = OpPQSIGKeyGen(input);
else if (ids.IsPQSIG_Sign(operation)) FuzzerOutput = OpPQSIGSign(input);
else if (ids.IsPQSIG_Verify(operation)) FuzzerOutput = OpPQSIGVerify(input);
