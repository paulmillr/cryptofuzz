import assert from 'node:assert/strict';
import path from 'node:path';
import { mutations, repositories } from './mutations.mjs';

const validPhases = new Set(['digest', 'kdfs', 'argon2', 'ciphers', 'fast', 'pairing', 'general', 'slh-dsa']);
const identities = new Set();

for (const project of Object.keys(repositories)) {
  const selected = mutations.filter((item) => item.project === project);
  assert.ok(selected.length >= 15, `${project} must define at least 15 mutations`);
  assert.equal(new Set(selected.map((item) => item.defectClass)).size, selected.length,
    `${project} defect classes must be distinct`);
  for (const item of selected) {
    const identity = `${item.project}:${item.id}`;
    assert.ok(!identities.has(identity), `duplicate mutation identity ${identity}`);
    identities.add(identity);
    assert.ok(item.id.length > 0 && item.defectClass.length > 0);
    assert.ok(item.from.length > 0 && item.to.length > 0 && item.from !== item.to);
    assert.ok(validPhases.has(item.phase), `invalid phase ${item.phase}`);
    assert.equal(path.isAbsolute(item.file), false, `${identity} file must be relative`);
    assert.equal(item.file.split(path.sep).includes('..'), false, `${identity} file escapes its checkout`);
    assert.ok(Number.isSafeInteger(item.occurrences ?? 1) && (item.occurrences ?? 1) > 0);
  }
}

console.log(`mutation definitions passed (${mutations.length} distinct defects)`);
