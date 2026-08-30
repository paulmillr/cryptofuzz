import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, readdir, readFile, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { decodeCase, encodeCase } from './cases.mjs';

export class Corpus {
  constructor(directory, phase, maxLength, validate) {
    this.directory = path.resolve(directory);
    this.phase = phase;
    this.maxLength = maxLength;
    this.validate = validate;
    this.entries = [];
    this.byOperation = new Map();
    this.hashes = new Set();
    this.filenames = new Set();
    this.entrySet = new WeakSet();
    this.hashByEntry = new WeakMap();
    this.featuresByEntry = new WeakMap();
    this.featureFrequency = new Map();
    this.scoreCache = new WeakMap();
    this.frequencyVersion = 0;
  }

  async load() {
    await mkdir(this.directory, { recursive: true });
    await this.refresh();
    return this.entries;
  }

  async refresh() {
    const filenames = (await readdir(this.directory)).filter((name) => name.endsWith('.json')).sort();
    const added = [];
    for (const filename of filenames) {
      if (this.filenames.has(filename)) continue;
      const serialized = await readFile(path.join(this.directory, filename), 'utf8');
      const testcase = this.validate(decodeCase(serialized), this.maxLength, this.phase);
      this.filenames.add(filename);
      if (this.#remember(testcase, this.#hash(serialized))) added.push(testcase);
    }
    return added;
  }

  #hash(serialized) {
    return createHash('sha256').update(serialized).digest('hex');
  }

  #remember(testcase, hash) {
    if (this.hashes.has(hash)) return false;
    this.hashes.add(hash);
    this.entries.push(testcase);
    this.entrySet.add(testcase);
    this.hashByEntry.set(testcase, hash);
    const entries = this.byOperation.get(testcase.operation) ?? [];
    entries.push(testcase);
    this.byOperation.set(testcase.operation, entries);
    return true;
  }

  /** Content hash of a corpus entry — matches its on-disk `<hash>.json` filename. */
  hashOf(testcase) {
    return this.hashByEntry.get(testcase);
  }

  pick(prng, operation) {
    const candidates = operation === undefined ? this.entries : this.byOperation.get(operation) ?? [];
    if (candidates.length === 0) return undefined;
    if (candidates.length === 1 || prng.bool(1, 4)) return prng.pick(candidates);
    let selected = prng.pick(candidates);
    let score = this.#rarityScore(selected);
    for (let index = 1; index < Math.min(4, candidates.length); index++) {
      const candidate = prng.pick(candidates);
      const candidateScore = this.#rarityScore(candidate);
      if (candidateScore > score) {
        selected = candidate;
        score = candidateScore;
      }
    }
    return selected;
  }

  setFeatures(testcase, features) {
    if (!this.entrySet.has(testcase)) return false;
    const known = this.featuresByEntry.get(testcase) ?? new Set();
    for (const feature of features) {
      if (known.has(feature)) continue;
      known.add(feature);
      this.featureFrequency.set(feature, (this.featureFrequency.get(feature) ?? 0) + 1);
      this.frequencyVersion++;
    }
    this.featuresByEntry.set(testcase, known);
    return true;
  }

  mutationEnergy(testcase) {
    const cached = this.scoreCache.get(testcase);
    if (cached?.version === this.frequencyVersion) return cached.energy;
    const features = this.featuresByEntry.get(testcase);
    if (features === undefined || features.size === 0) return 1;
    let rarest = Infinity;
    for (const feature of features) rarest = Math.min(rarest, this.featureFrequency.get(feature) ?? 1);
    const energy = rarest <= 1 ? 4 : rarest === 2 ? 3 : rarest <= 4 ? 2 : 1;
    const score = this.#calculateRarityScore(features, rarest);
    this.scoreCache.set(testcase, { version: this.frequencyVersion, score, energy });
    return energy;
  }

  #rarityScore(testcase) {
    const cached = this.scoreCache.get(testcase);
    if (cached?.version === this.frequencyVersion) return cached.score;
    const features = this.featuresByEntry.get(testcase);
    if (features === undefined || features.size === 0) return 0;
    let rarest = Infinity;
    for (const feature of features) rarest = Math.min(rarest, this.featureFrequency.get(feature) ?? 1);
    const score = this.#calculateRarityScore(features, rarest);
    const energy = rarest <= 1 ? 4 : rarest === 2 ? 3 : rarest <= 4 ? 2 : 1;
    this.scoreCache.set(testcase, { version: this.frequencyVersion, score, energy });
    return score;
  }

  #calculateRarityScore(features, rarest) {
    let inverse = 0;
    for (const feature of features) {
      const frequency = this.featureFrequency.get(feature) ?? 1;
      inverse += 1 / frequency;
    }
    return 1 / rarest + inverse / features.size / 1024;
  }

  async add(testcase) {
    this.validate(testcase, this.maxLength, this.phase);
    const serialized = encodeCase(testcase);
    const hash = this.#hash(serialized);
    if (!this.#remember(testcase, hash)) return false;
    const filename = path.join(this.directory, `${hash}.json`);
    const temporary = path.join(this.directory, `.${hash}.${process.pid}.${randomUUID()}.tmp`);
    await writeFile(temporary, serialized, { flag: 'wx' });
    try {
      try {
        // Publish only after the complete JSON is on disk. Concurrent workers either
        // create the same content-addressed link or observe EEXIST.
        await link(temporary, filename);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    } finally {
      await unlink(temporary);
    }
    this.filenames.add(path.basename(filename));
    return true;
  }
}
