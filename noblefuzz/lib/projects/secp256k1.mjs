import { createStandaloneSecp256k1Target } from './secp256k1-target.mjs';
import { createStandaloneCurveProject } from './standalone-curve.mjs';

export const SECP256K1_OPERATIONS = Object.freeze([
  'ECC_PrivateToPublic', 'ECC_ValidatePubkey', 'ECDH_Derive',
  'ECDSA_Sign', 'ECDSA_Verify', 'ECDSA_Recover',
  'Schnorr_Sign', 'Schnorr_Verify',
  'ECC_Point_Add', 'ECC_Point_Sub', 'ECC_Point_Mul', 'ECC_Point_Neg', 'ECC_Point_Dbl',
]);

export const SECP256K1_RAW_FIELDS = Object.freeze({
  ECC_PrivateToPublic: ['privateKey'],
  ECC_ValidatePubkey: ['publicKey'],
  ECDH_Derive: ['privateKey', 'publicKey'],
  ECDSA_Sign: ['privateKey'],
  ECDSA_Verify: ['publicKey', 'signature'],
  ECDSA_Recover: ['signature'],
  Schnorr_Sign: ['privateKey', 'aux'],
  Schnorr_Verify: ['publicKey', 'signature'],
  ECC_Point_Add: ['pointA', 'pointB'],
  ECC_Point_Sub: ['pointA', 'pointB'],
  ECC_Point_Mul: ['pointA', 'scalar'],
  ECC_Point_Neg: ['pointA'],
  ECC_Point_Dbl: ['pointA'],
});

export const secp256k1Project = createStandaloneCurveProject({
  name: 'noble-secp256k1',
  packageName: '@noble/secp256k1',
  operations: SECP256K1_OPERATIONS,
  rawFields: SECP256K1_RAW_FIELDS,
  fixedMessageOperations: ['Schnorr_Sign', 'Schnorr_Verify'],
  createTarget: createStandaloneSecp256k1Target,
});
