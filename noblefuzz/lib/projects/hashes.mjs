import { caseFeatures, generateCase, mutateCase, PHASE_OPERATIONS, seedCases, validateCase } from '../cases.mjs';
import { createTarget } from '../target.mjs';
import { executeCase } from '../verifier.mjs';

const KDF_OPERATION_BAG = ['HMAC', 'HMAC', 'HMAC', 'HMAC', 'HKDF', 'HKDF', 'PBKDF2', 'PBKDF2', 'Scrypt'];

export const hashesProject = {
  name: 'noble-hashes',
  packageName: '@noble/hashes',
  phases: Object.keys(PHASE_OPERATIONS),
  createTarget,
  operations(phase) {
    return PHASE_OPERATIONS[phase];
  },
  chooseOperation(phase, prng) {
    if (phase === 'kdfs') return prng.pick(KDF_OPERATION_BAG);
    return PHASE_OPERATIONS[phase]?.[0];
  },
  generateCase(phase, prng, target, maxLength, operation) {
    return generateCase(phase, prng, target.algorithms, maxLength, operation);
  },
  mutateCase(base, phase, prng, target, maxLength) {
    return mutateCase(base, phase, prng, target.algorithms, maxLength);
  },
  seedCases(phase, prng, target, maxLength) {
    return seedCases(phase, prng, target.algorithms, maxLength);
  },
  validateCase,
  caseFeatures,
  executeCase,
  sampleMask(phase) {
    return phase === 'digest' ? 255 : phase === 'kdfs' ? 15 : 0;
  },
  yieldInterval(phase) {
    return phase === 'digest' ? 4096 : phase === 'kdfs' ? 32 : 1;
  },
};
