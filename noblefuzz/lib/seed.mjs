import { createHash } from 'node:crypto';

const MAX_SEED = (1n << 256n) - 1n;
const SEED_ERROR = 'seed must be a positive decimal or 0x-prefixed hexadecimal integer of at most 256 bits';

export function normalizeSeed(seed) {
  let value;
  try {
    if (typeof seed === 'bigint') {
      value = seed;
    } else if (typeof seed === 'number') {
      if (!Number.isSafeInteger(seed)) throw new Error(SEED_ERROR);
      value = BigInt(seed);
    } else if (typeof seed === 'string') {
      const text = seed.trim();
      if (!/^(?:[1-9][0-9]*|0[xX][0-9a-fA-F]+)$/.test(text)) throw new Error(SEED_ERROR);
      value = BigInt(text);
    } else {
      throw new Error(SEED_ERROR);
    }
  } catch (error) {
    if (error.message === SEED_ERROR) throw error;
    throw new Error(SEED_ERROR);
  }
  if (value <= 0n || value > MAX_SEED) throw new Error(SEED_ERROR);
  return `0x${value.toString(16).padStart(64, '0')}`;
}

export function seedBytes(seed) {
  return Buffer.from(normalizeSeed(seed).slice(2), 'hex');
}

export function deriveSeed(seed, domain) {
  if (typeof domain !== 'string' || domain.length === 0 || domain.includes('\0')) {
    throw new Error('seed derivation domain must be a non-empty string without NUL bytes');
  }
  const digest = createHash('sha256')
    .update('noblefuzz-seed-v2\0')
    .update(seedBytes(seed))
    .update('\0')
    .update(domain)
    .digest('hex');
  return `0x${digest}`;
}
