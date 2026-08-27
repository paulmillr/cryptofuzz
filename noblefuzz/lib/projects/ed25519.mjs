import { createStandaloneEd25519Target } from './ed25519-target.mjs';
import { createStandaloneCurveProject } from './standalone-curve.mjs';

export const ED25519_OPERATIONS = Object.freeze([
  'ECC_PrivateToPublic', 'ECC_ValidatePubkey', 'ECDSA_Sign', 'ECDSA_Verify',
  'ECC_Point_Add', 'ECC_Point_Sub', 'ECC_Point_Mul', 'ECC_Point_Neg', 'ECC_Point_Dbl',
]);

export const ED25519_RAW_FIELDS = Object.freeze({
  ECC_PrivateToPublic: ['privateKey'],
  ECC_ValidatePubkey: ['publicKey'],
  ECDSA_Sign: ['privateKey'],
  ECDSA_Verify: ['publicKey', 'signature'],
  ECC_Point_Add: ['pointA', 'pointB'],
  ECC_Point_Sub: ['pointA', 'pointB'],
  ECC_Point_Mul: ['pointA', 'scalar'],
  ECC_Point_Neg: ['pointA'],
  ECC_Point_Dbl: ['pointA'],
});

export const ed25519Project = createStandaloneCurveProject({
  name: 'noble-ed25519',
  packageName: '@noble/ed25519',
  operations: ED25519_OPERATIONS,
  rawFields: ED25519_RAW_FIELDS,
  createTarget: createStandaloneEd25519Target,
});
