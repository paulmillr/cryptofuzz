import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { decodeCase, encodeCase, validateCase } from './lib/cases.mjs';
import { Corpus } from './lib/corpus.mjs';
import { runEngine } from './lib/engine.mjs';
import { GuidanceTracker, instrumentSource } from './lib/instrumenter.mjs';
import { PRNG } from './lib/prng.mjs';
import { minimizeFailure, reduceCorpus } from './lib/reducer.mjs';
import { createTarget } from './lib/target.mjs';
import { executeCase } from './lib/verifier.mjs';
import { deriveWorkerSeed, resolveWorkerCount } from './lib/workers.mjs';

const sourceDirectory = process.env.NOBLE_SOURCE_DIR;
const target = await createTarget(sourceDirectory);

const randomA = new PRNG(123);
const randomB = new PRNG(123);
assert.deepEqual(Array.from({ length: 100 }, () => randomA.next()), Array.from({ length: 100 }, () => randomB.next()));
assert.equal(resolveWorkerCount(1, 24), 1);
assert.equal(resolveWorkerCount(12, 24), 12);
assert.equal(resolveWorkerCount('auto', 24), 10);
assert.equal(resolveWorkerCount('-1', 8), 7);
assert.equal(resolveWorkerCount('50%', 8), 4);
assert.equal(resolveWorkerCount('0.5', 8), 4);
assert.throws(() => resolveWorkerCount(0, 8), /invalid worker count/);
assert.throws(() => resolveWorkerCount('2x', 8), /invalid worker count/);
assert.throws(() => resolveWorkerCount('200%', 8), /invalid worker count/);
assert.equal(deriveWorkerSeed(123, 0), 123);
assert.equal(deriveWorkerSeed(123, 1), deriveWorkerSeed(123, 1));
assert.notEqual(deriveWorkerSeed(123, 1), deriveWorkerSeed(123, 2));

const instrumented = instrumentSource(`
globalThis.__noblefuzzInstrumentTest = (value) => {
  if (value > 0) return value === 1 ? 'one' : 'positive';
  if (value === 0) return 'zero';
  return value || -1;
};
`, 'instrument-test.js');
const tracker = new GuidanceTracker();
globalThis.__noblefuzzHit = tracker.hit;
Function(instrumented)();
const guidedRun = (value) => {
  tracker.begin();
  const result = globalThis.__noblefuzzInstrumentTest(value);
  return { result, features: tracker.finish() };
};
const positiveGuidance = guidedRun(2);
const zeroGuidance = guidedRun(0);
const negativeGuidance = guidedRun(-2);
assert.equal(positiveGuidance.result, 'positive');
assert.equal(zeroGuidance.result, 'zero');
assert.equal(negativeGuidance.result, -2);
assert.ok(positiveGuidance.features.length > 0);
assert.notDeepEqual(positiveGuidance.features, zeroGuidance.features);
assert.notDeepEqual(zeroGuidance.features, negativeGuidance.features);
delete globalThis.__noblefuzzInstrumentTest;
delete globalThis.__noblefuzzHit;

const roundTrip = {
  version: 1,
  operation: 'Digest',
  digest: 'SHA256',
  message: Uint8Array.from([0x61, 0x62, 0x63]),
  chunks: [1, 0, 2],
};
assert.deepEqual(decodeCase(encodeCase(roundTrip)), roundTrip);
assert.equal(Buffer.from(executeCase(target, roundTrip)).toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

const hmacCase = {
  version: 1,
  operation: 'HMAC',
  digest: 'SHA256',
  key: new Uint8Array(20).fill(0x0b),
  message: Uint8Array.from(Buffer.from('Hi There')),
  chunks: [2, 0, 6],
};
assert.equal(Buffer.from(executeCase(target, hmacCase)).toString('hex'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

const hkdfCase = {
  version: 1,
  operation: 'HKDF',
  digest: 'SHA256',
  password: new Uint8Array(22).fill(0x0b),
  salt: Uint8Array.from(Buffer.from('000102030405060708090a0b0c', 'hex')),
  info: Uint8Array.from(Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')),
  keySize: 42,
};
assert.equal(Buffer.from(executeCase(target, hkdfCase)).toString('hex'), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

const pbkdf2Case = {
  version: 1,
  operation: 'PBKDF2',
  digest: 'SHA256',
  password: Uint8Array.from(Buffer.from('password')),
  salt: Uint8Array.from(Buffer.from('salt')),
  iterations: 1,
  keySize: 32,
};
assert.equal(Buffer.from(executeCase(target, pbkdf2Case)).toString('hex'), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');

const scryptCase = {
  version: 1,
  operation: 'Scrypt',
  password: Uint8Array.from(Buffer.from('password')),
  salt: Uint8Array.from(Buffer.from('NaCl')),
  N: 1024,
  r: 8,
  p: 4,
  keySize: 64,
};
executeCase(target, scryptCase);
assert.throws(() => validateCase({ ...scryptCase, p: 5 }, 4096, 'kdfs'), /invalid scrypt parameters/);

const argon2Case = {
  version: 1,
  operation: 'Argon2',
  type: 2,
  password: Uint8Array.from(Buffer.from('password')),
  salt: Uint8Array.from(Buffer.from('somesalt')),
  iterations: 1,
  memory: 32,
  p: 4,
  keySize: 32,
};
executeCase(target, argon2Case);
for (let type = 0; type < 3; type++) {
  for (let p = 1; p <= 4; p++) executeCase(target, { ...argon2Case, type, p });
}
assert.throws(() => validateCase({ ...argon2Case, p: 5, memory: 40 }, 4096, 'argon2'), /invalid Argon2 parameters/);

const reducerProject = {
  validateCase(testcase) {
    if (!(testcase.payload instanceof Uint8Array)) throw new Error('invalid reducer testcase');
    return testcase;
  },
  executeCase(target, testcase) {
    if (target.fail && testcase.payload.includes(0x42)) throw new Error('marker failure');
    return testcase.payload.length;
  },
  caseFeatures() { return ['same-feature']; },
};
const minimized = minimizeFailure(reducerProject, { fail: true }, { payload: Uint8Array.of(1, 2, 0x42, 3) }, 4096);
assert.deepEqual(minimized.testcase.payload, Uint8Array.of(0x42));
assert.ok(minimized.attempts > 0);
const reduced = reduceCorpus(reducerProject, { fail: false },
  [{ payload: new Uint8Array(64) }, { payload: Uint8Array.of(1) }], 4096);
assert.equal(reduced.outputCases, 1);
assert.deepEqual(reduced.cases[0].payload, Uint8Array.of(1));

const temporary = await mkdtemp(path.join(os.tmpdir(), 'noblefuzz-test-'));
try {
  const sharedA = new Corpus(path.join(temporary, 'shared-corpus'), 'digest', 4096, validateCase);
  const sharedB = new Corpus(path.join(temporary, 'shared-corpus'), 'digest', 4096, validateCase);
  await sharedA.load();
  await sharedB.load();
  await sharedA.add(roundTrip);
  assert.equal((await sharedB.refresh()).length, 1);
  assert.deepEqual(sharedB.entries[0], roundTrip);
  const commonCase = { ...roundTrip, message: Uint8Array.of(1), chunks: [1] };
  await sharedA.add(commonCase);
  sharedA.setFeatures(roundTrip, ['common', 'rare']);
  sharedA.setFeatures(commonCase, ['common']);
  assert.ok(sharedA.mutationEnergy(roundTrip) > sharedA.mutationEnergy(commonCase));

  const stats = await runEngine({
    phase: 'digest',
    runs: 100,
    seed: 999,
    maxLength: 4096,
    corpusDirectory: path.join(temporary, 'corpus'),
    artifactDirectory: path.join(temporary, 'artifacts'),
    sourceDirectory,
    quiet: true,
  });
  assert.ok(stats.runs >= 100);
  assert.ok(stats.runsPerSecond > 1000);
  assert.ok(stats.features >= target.algorithms.length);
  const stored = JSON.parse(await readFile(path.join(temporary, 'artifacts', 'stats-digest.json'), 'utf8'));
  assert.equal(stored.engine, 'noblefuzz');

  const kdfStats = await runEngine({
    phase: 'kdfs',
    runs: 5,
    seed: 1000,
    maxLength: 4096,
    corpusDirectory: path.join(temporary, 'kdf-corpus'),
    artifactDirectory: path.join(temporary, 'kdf-artifacts'),
    sourceDirectory,
    quiet: true,
  });
  for (const operation of ['HMAC', 'HKDF', 'PBKDF2', 'Scrypt']) assert.ok(kdfStats.operations[operation].runs > 0);

  const coverageStats = await runEngine({
    phase: 'digest',
    runs: 6,
    seed: 1002,
    maxLength: 4096,
    corpusDirectory: path.join(temporary, 'coverage-corpus'),
    artifactDirectory: path.join(temporary, 'coverage-artifacts'),
    sourceDirectory,
    coverageEvery: 2,
    quiet: true,
  });
  assert.equal(coverageStats.coverageSamples, 3);
  assert.ok(coverageStats.coverageFeatures > 0);
  const coveredCases = await Promise.all((await readdir(path.join(temporary, 'coverage-corpus')))
    .filter((name) => name.endsWith('.json'))
    .map(async (name) => decodeCase(await readFile(path.join(temporary, 'coverage-corpus', name), 'utf8'))));
  assert.ok(coveredCases.some((testcase) => Array.isArray(testcase.coverage) && testcase.coverage.length > 0));

  const cliArguments = [
    'cli.mjs', 'fuzz', '--phase', 'digest', '--runs', '10', '--seed', '1001', '--max-len', '4096',
    '--workers', '2', '--timeout', '10', '--corpus', path.join(temporary, 'cli-corpus'),
    '--guidance-workers', '1', '--artifacts', path.join(temporary, 'cli-artifacts'), '--quiet',
  ];
  if (sourceDirectory) cliArguments.push('--source-dir', sourceDirectory);
  const cli = spawnSync(process.execPath, cliArguments, { cwd: new URL('.', import.meta.url), encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stderr);
  const cliStats = JSON.parse(await readFile(path.join(temporary, 'cli-artifacts', 'stats-digest.json'), 'utf8'));
  assert.equal(cliStats.workers, 2);
  assert.equal(cliStats.guidanceWorkers, 1);
  assert.deepEqual(cliStats.workerRoles, ['guidance', 'throughput']);
  assert.ok(cliStats.guidanceCases > 0);
  assert.ok(cliStats.guidanceFeatures > 0);
  assert.deepEqual(cliStats.workerSeeds, [1001, deriveWorkerSeed(1001, 1)]);
  assert.equal(cliStats.operations.Digest.runs, cliStats.runs);
  const workerStats = (await readdir(path.join(temporary, 'cli-artifacts')))
    .filter((name) => /^stats-digest-worker-\d+\.json$/.test(name));
  assert.equal(workerStats.length, 2);
  const corpusFiles = await readdir(path.join(temporary, 'cli-corpus'));
  assert.equal(corpusFiles.some((name) => name.endsWith('.tmp')), false);
  for (const filename of corpusFiles) decodeCase(await readFile(path.join(temporary, 'cli-corpus', filename), 'utf8'));
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log('noblefuzz tests passed');
await import('./contract-test.mjs');
await import('./mutation/test.mjs');
