import { encodeCase } from './cases.mjs';
import { byteSize, cloneCase } from './mutation.mjs';

function failureIdentity(error) {
  const message = String(error?.message ?? error).replace(/; reproducer: .*$/, '');
  return `${error?.name ?? 'Error'}\0${message}`;
}

function repairDependentFields(testcase, field) {
  if (field === 'message' && Array.isArray(testcase.chunks)) testcase.chunks = [testcase.message.length];
}

export function minimizeFailure(project, target, original, maxLength, phase) {
  project.validateCase(original, maxLength, phase);
  let identity;
  try {
    project.executeCase(target, original);
  } catch (error) {
    identity = failureIdentity(error);
  }
  if (identity === undefined) throw new Error('testcase does not currently reproduce a failure');

  let testcase = cloneCase(original);
  delete testcase.coverage;
  let attempts = 0;
  let reductions = 0;
  const reproduces = (candidate) => {
    attempts++;
    try {
      project.validateCase(candidate, maxLength, phase);
      project.executeCase(target, candidate);
      return false;
    } catch (error) {
      // Invalid candidates are mutations of the reducer rather than target
      // failures, so never allow validation errors to become the new oracle.
      try {
        project.validateCase(candidate, maxLength, phase);
      } catch {
        return false;
      }
      return failureIdentity(error) === identity;
    }
  };
  const accept = (candidate) => {
    if (!reproduces(candidate)) return false;
    testcase = candidate;
    reductions++;
    return true;
  };

  for (const field of Object.keys(testcase).filter((key) => testcase[key] instanceof Uint8Array)) {
    let granularity = 2;
    while (testcase[field].length > 0) {
      const length = testcase[field].length;
      const chunk = Math.ceil(length / granularity);
      let reduced = false;
      for (let start = 0; start < length; start += chunk) {
        const candidate = cloneCase(testcase);
        candidate[field] = Uint8Array.from([
          ...testcase[field].subarray(0, start),
          ...testcase[field].subarray(Math.min(length, start + chunk)),
        ]);
        repairDependentFields(candidate, field);
        if (accept(candidate)) {
          granularity = Math.max(2, granularity - 1);
          reduced = true;
          break;
        }
      }
      if (reduced) continue;
      if (granularity >= length) break;
      granularity = Math.min(length, granularity * 2);
    }
    if (testcase[field].length > 0) {
      const candidate = cloneCase(testcase);
      candidate[field].fill(0);
      accept(candidate);
    }
    for (let index = 0; index < testcase[field].length; index++) {
      if (testcase[field][index] === 0) continue;
      const candidate = cloneCase(testcase);
      candidate[field][index] = 0;
      accept(candidate);
    }
  }

  for (const field of Object.keys(testcase).filter((key) => Number.isSafeInteger(testcase[key]))) {
    for (const value of [0, 1, 2, 3, 4, 8, 16]) {
      if (value >= testcase[field]) continue;
      const candidate = cloneCase(testcase);
      candidate[field] = value;
      accept(candidate);
    }
  }

  return {
    testcase,
    identity,
    attempts,
    reductions,
    originalBytes: byteSize(original),
    minimizedBytes: byteSize(testcase),
    originalSerializedBytes: Buffer.byteLength(encodeCase(original)),
    minimizedSerializedBytes: Buffer.byteLength(encodeCase(testcase)),
  };
}

export function reduceCorpus(project, target, cases, maxLength, phase) {
  const unique = new Map();
  for (const testcase of cases) {
    project.validateCase(testcase, maxLength, phase);
    const serialized = encodeCase(testcase);
    if (unique.has(serialized)) continue;
    const result = project.executeCase(target, testcase);
    const recordedCoverage = testcase.coverage ?? [];
    if (!Array.isArray(recordedCoverage) || recordedCoverage.some((feature) => typeof feature !== 'string')) {
      throw new Error('invalid recorded coverage metadata');
    }
    unique.set(serialized, {
      testcase,
      serialized,
      size: Buffer.byteLength(serialized),
      features: new Set([...project.caseFeatures(testcase, target, result), ...recordedCoverage]),
      keep: true,
    });
  }
  const records = [...unique.values()];
  const counts = new Map();
  for (const record of records) {
    for (const feature of record.features) counts.set(feature, (counts.get(feature) ?? 0) + 1);
  }
  // Discard the largest redundant cases first. This preserves the complete
  // semantic feature union while preferring compact mutation seeds.
  for (const record of [...records].sort((a, b) => b.size - a.size)) {
    if ([...record.features].some((feature) => counts.get(feature) <= 1)) continue;
    record.keep = false;
    for (const feature of record.features) counts.set(feature, counts.get(feature) - 1);
  }
  const kept = records.filter((record) => record.keep)
    .sort((a, b) => a.serialized.localeCompare(b.serialized)).map((record) => record.testcase);
  return {
    cases: kept,
    inputCases: cases.length,
    uniqueCases: records.length,
    outputCases: kept.length,
    features: counts.size,
    inputBytes: records.reduce((sum, record) => sum + record.size, 0),
    outputBytes: records.filter((record) => record.keep).reduce((sum, record) => sum + record.size, 0),
  };
}
