function operationCost(operation) {
  if (operation.sampledRuns === 0) return 0;
  return operation.sampledMilliseconds * 1e6 / operation.sampledRuns * operation.runs;
}

export function mergeWorkerStats(results, { seed, corpusEntries, elapsedSeconds } = {}) {
  if (!Array.isArray(results) || results.length === 0) throw new Error('cannot merge an empty worker result set');
  const ordered = [...results].sort((a, b) => (a.workerId ?? 0) - (b.workerId ?? 0));
  const first = ordered[0];
  const operationNames = Object.keys(first.operations);
  for (const result of ordered) {
    if (result.project !== first.project || result.phase !== first.phase || result.maxLength !== first.maxLength) {
      throw new Error('worker result metadata differs');
    }
    if (
      Object.keys(result.operations).length !== operationNames.length ||
      operationNames.some((name) => result.operations[name] === undefined)
    ) {
      throw new Error('worker result operations differ');
    }
  }

  const operations = {};
  let estimatedTotalNanoseconds = 0;
  for (const name of operationNames) {
    const values = ordered.map((result) => result.operations[name]);
    const runs = values.reduce((sum, value) => sum + value.runs, 0);
    const sampledRuns = values.reduce((sum, value) => sum + value.sampledRuns, 0);
    const sampledMilliseconds = values.reduce((sum, value) => sum + value.sampledMilliseconds, 0);
    operations[name] = {
      runs,
      sampledRuns,
      sampledMilliseconds,
      averageSampleMicroseconds: sampledRuns === 0 ? 0 : sampledMilliseconds * 1e3 / sampledRuns,
      estimatedShare: 0,
    };
    estimatedTotalNanoseconds += operationCost(operations[name]);
  }
  for (const operation of Object.values(operations)) {
    const cost = operationCost(operation);
    operation.estimatedShare = estimatedTotalNanoseconds === 0 ? 0 : cost / estimatedTotalNanoseconds;
  }

  const featureNames = [...new Set(ordered.flatMap((result) => result.featureNames ?? []))].sort();
  const effectiveElapsed = elapsedSeconds ?? Math.max(...ordered.map((result) => result.elapsedSeconds));
  const runs = ordered.reduce((sum, result) => sum + result.runs, 0);
  return {
    engine: first.engine,
    version: first.version,
    project: first.project,
    phase: first.phase,
    seed: seed ?? first.seed,
    workerSeeds: ordered.map((result) => result.seed),
    workerRoles: ordered.map((result) => result.workerRole ?? 'throughput'),
    workers: ordered.length,
    maxLength: first.maxLength,
    sourceDirectory: first.sourceDirectory,
    startedAt: ordered.map((result) => result.startedAt).sort()[0],
    finishedAt: ordered.map((result) => result.finishedAt).sort().at(-1),
    runs,
    initialCorpus: Math.max(...ordered.map((result) => result.initialCorpus)),
    importedCorpus: ordered.reduce((sum, result) => sum + (result.importedCorpus ?? 0), 0),
    corpusEntries: corpusEntries ?? Math.max(...ordered.map((result) => result.corpusEntries)),
    features: featureNames.length > 0 ? featureNames.length : Math.max(...ordered.map((result) => result.features)),
    coverageEvery: first.coverageEvery ?? null,
    coverageSeconds: first.coverageSeconds ?? null,
    coverageSamples: ordered.reduce((sum, result) => sum + (result.coverageSamples ?? 0), 0),
    coverageFeatures: featureNames.filter((feature) => feature.startsWith('v8:')).length,
    guidanceCases: ordered.reduce((sum, result) => sum + (result.guidanceCases ?? 0), 0),
    guidanceFeatures: featureNames.filter((feature) => feature.startsWith('js:')).length,
    favoredRuns: ordered.reduce((sum, result) => sum + (result.favoredRuns ?? 0), 0),
    mutationSteps: ordered.reduce((sum, result) => sum + (result.mutationSteps ?? 0), 0),
    elapsedSeconds: effectiveElapsed,
    runsPerSecond: effectiveElapsed === 0 ? 0 : runs / effectiveElapsed,
    operations,
  };
}
