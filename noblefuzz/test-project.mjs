import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runEngine } from './lib/engine.mjs';
import { PRNG } from './lib/prng.mjs';
import { getProject } from './lib/projects/index.mjs';

const projectName = process.argv[2] ?? process.env.NOBLE_PROJECT;
if (!projectName) throw new Error('usage: node test-project.mjs <noble-project>');
const project = getProject(projectName);
const sourceDirectory = process.env.NOBLE_SOURCE_DIR;
const maxLength = projectName === 'noble-post-quantum' ? 65536 : 4096;
const target = await project.createTarget(sourceDirectory);
const temporary = await mkdtemp(path.join(os.tmpdir(), `noblefuzz-${projectName}-`));
try {
  for (const [index, phase] of project.phases.entries()) {
    const stats = await runEngine({
      project: projectName,
      phase,
      runs: 1,
      seed: 0x1000 + index,
      maxLength,
      corpusDirectory: path.join(temporary, `corpus-${phase}`),
      artifactDirectory: path.join(temporary, `artifacts-${phase}`),
      sourceDirectory,
      quiet: true,
    });
    assert.equal(stats.project, projectName);
    for (const operation of project.operations(phase)) {
      assert.ok(stats.operations[operation].runs > 0, `${operation} was not seeded`);
    }
    if (projectName === 'noble-ciphers' || projectName === 'noble-post-quantum') {
      for (const operation of project.operations(phase)) {
        assert.ok(stats.featureNames.includes(`${operation}:mode:raw`), `${operation} raw-input mode was not seeded`);
      }
    }
    if (['noble-curves', 'noble-secp256k1', 'noble-ed25519'].includes(projectName) && phase === 'fast') {
      assert.ok(stats.featureNames.some((feature) => feature.endsWith(':mode:raw')), 'curve raw-input modes were not seeded');
    }
    if (projectName === 'noble-secp256k1' || projectName === 'noble-ed25519') {
      for (const operation of project.operations(phase)) {
        assert.ok(stats.featureNames.includes(`${operation}:mode:raw`), `${operation} raw-input mode was not seeded`);
      }
    }
    if (projectName === 'noble-curves' && phase === 'fast') {
      const rawVerify = project.seedCases(phase, new PRNG(0x2000), target, maxLength)
        .find((testcase) => testcase.operation === 'BLS_Verify' && testcase.mode === 'raw');
      assert.ok(rawVerify, 'raw BLS verification was not seeded');
      const rejected = project.executeCase(target, { ...rawVerify, dst: new Uint8Array(), matched: false });
      assert.equal(rejected.outcome, 'reject');
    }
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}
console.log(`${projectName} source-checkout tests passed`);
