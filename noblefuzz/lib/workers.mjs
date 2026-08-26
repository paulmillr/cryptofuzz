import { availableParallelism } from 'node:os';
import { deriveSeed } from './seed.mjs';

const MAX_WORKERS = 256;
const RELATIVE_WORKER_CAP = 10;

export function parseWorkerSpec(value = 1) {
  const raw = String(value).trim().toLowerCase();
  if (raw === 'auto') return Infinity;
  const percent = raw.endsWith('%');
  const numeric = Number(percent ? raw.slice(0, -1) : raw) / (percent ? 100 : 1);
  const ratio = numeric > 0 && numeric < 1;
  const valid =
    Number.isFinite(numeric) &&
    numeric !== 0 &&
    Math.abs(numeric) <= MAX_WORKERS &&
    (!percent || (numeric > 0 && numeric <= 1)) &&
    (ratio || numeric === 1 || Number.isSafeInteger(numeric));
  if (!valid) {
    throw new Error(`invalid worker count: ${value}; use a count, -N for cores minus N, N% of cores, or auto`);
  }
  return percent && numeric === 1 ? Infinity : numeric;
}

export function resolveWorkerCount(value = 1, parallelism = availableParallelism()) {
  if (!Number.isSafeInteger(parallelism) || parallelism < 1) throw new Error('available parallelism must be positive');
  const spec = parseWorkerSpec(value);
  const count =
    spec === Infinity ? parallelism : spec < 0 ? parallelism + spec : spec < 1 ? Math.floor(parallelism * spec) : spec;
  const cap = spec === Infinity || spec < 1 ? RELATIVE_WORKER_CAP : MAX_WORKERS;
  return Math.max(1, Math.min(count, cap));
}

export function deriveWorkerSeed(seed, workerId, context = 'default') {
  if (!Number.isSafeInteger(workerId) || workerId < 0) throw new Error('worker id must be a non-negative integer');
  if (typeof context !== 'string' || context.length === 0 || context.includes('\0')) {
    throw new Error('worker seed context must be a non-empty string without NUL bytes');
  }
  return deriveSeed(seed, JSON.stringify(['worker', context, workerId]));
}
