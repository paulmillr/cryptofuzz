import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setImmediate as yieldToEvents } from 'node:timers/promises';
import { encodeCase } from './cases.mjs';
import { Corpus } from './corpus.mjs';
import { CoverageSampler } from './coverage.mjs';
import { enableGuidance } from './guidance.mjs';
import { PRNG } from './prng.mjs';
import { normalizeSeed } from './seed.mjs';
import { getProject } from './projects/index.mjs';

function safeError(error) {
  return {
    name: error?.name ?? 'Error',
    message: error?.message ?? String(error),
    stack: error?.stack,
    actual: error?.actual,
    expected: error?.expected,
  };
}

async function saveFailure(directory, phase, seed, testcase, error, workerId, baseSeed) {
  await mkdir(directory, { recursive: true });
  const serialized = encodeCase(testcase);
  const id = createHash('sha256').update(serialized).digest('hex').slice(0, 16);
  const worker = workerId === undefined ? '' : `-worker-${workerId}`;
  const base = `failure-${phase}${worker}-${id}`;
  const testcasePath = path.join(directory, `${base}.json`);
  const reportPath = path.join(directory, `${base}.report.json`);
  await writeFile(testcasePath, serialized);
  await writeFile(reportPath, `${JSON.stringify({ phase, seed, baseSeed, workerId, testcase: path.basename(testcasePath), error: safeError(error) }, null, 2)}\n`);
  return testcasePath;
}

function caseFeatureNames(testcase, target, project, result, capturedCoverage = []) {
  const recordedCoverage = testcase.coverage ?? [];
  if (!Array.isArray(recordedCoverage) || recordedCoverage.some((feature) => typeof feature !== 'string')) {
    throw new Error('invalid recorded coverage metadata');
  }
  return [...new Set([...project.caseFeatures(testcase, target, result), ...recordedCoverage, ...capturedCoverage])];
}

function addFeatures(globalFeatures, names) {
  const added = [];
  for (const feature of names) {
    if (!globalFeatures.has(feature)) {
      globalFeatures.add(feature);
      added.push(feature);
    }
  }
  return added;
}

function emptyOperationStats() {
  return { runs: 0, sampledRuns: 0, sampledNanoseconds: 0 };
}

function printableStats(stats) {
  const operations = {};
  let estimatedTotalNanoseconds = 0;
  const estimated = {};
  for (const [name, value] of Object.entries(stats.operations)) {
    estimated[name] = value.sampledRuns === 0 ? 0 : value.sampledNanoseconds / value.sampledRuns * value.runs;
    estimatedTotalNanoseconds += estimated[name];
  }
  for (const [name, value] of Object.entries(stats.operations)) {
    operations[name] = {
      runs: value.runs,
      sampledRuns: value.sampledRuns,
      sampledMilliseconds: value.sampledNanoseconds / 1e6,
      averageSampleMicroseconds: value.sampledRuns === 0 ? 0 : value.sampledNanoseconds / value.sampledRuns / 1e3,
      estimatedShare: estimatedTotalNanoseconds === 0 ? 0 : estimated[name] / estimatedTotalNanoseconds,
    };
  }
  return {
    ...stats,
    operations,
    sampledNanoseconds: undefined,
    runsPerSecond: stats.elapsedSeconds === 0 ? 0 : stats.runs / stats.elapsedSeconds,
  };
}

function featureCoordinator(workerId) {
  if (process.send === undefined) {
    return { claim: async (features) => features, sync() {}, close() {} };
  }
  let requestId = 0;
  const pending = new Map();
  const receive = (message) => {
    if (message?.type !== 'feature-claim-result') return;
    const resolve = pending.get(message.requestId);
    if (resolve === undefined) return;
    pending.delete(message.requestId);
    resolve(message.accepted);
  };
  process.on('message', receive);
  return {
    claim(features) {
      if (features.length === 0) return Promise.resolve([]);
      const id = requestId++;
      return new Promise((resolve, reject) => {
        pending.set(id, resolve);
        process.send({ type: 'feature-claim', workerId, requestId: id, features }, (error) => {
          if (!error) return;
          pending.delete(id);
          reject(error);
        });
      });
    },
    sync(features) {
      if (features.length > 0) process.send({ type: 'feature-sync', workerId, features }, () => {});
    },
    close(disconnect = false) {
      process.removeListener('message', receive);
      // A message listener references Node's IPC channel. On a testcase failure there is no
      // result message to send afterwards, so leaving the channel referenced strands the worker
      // until the supervisor watchdog fires. Successful workers can still send their final result
      // through an unreferenced channel; it simply no longer keeps the event loop alive by itself.
      process.channel?.unref();
      if (disconnect && process.connected) process.disconnect();
    },
  };
}

export async function runEngine(options) {
  const {
    project: projectName = 'noble-hashes',
    phase,
    seconds,
    runs: runLimit,
    seed,
    maxLength,
    corpusDirectory,
    artifactDirectory,
    sourceDirectory,
    quiet = false,
    workerId,
    baseSeed,
    bootstrap = true,
    coverageEvery,
    coverageSeconds,
    guidance = false,
  } = options;
  const normalizedSeed = normalizeSeed(seed);
  const normalizedBaseSeed = normalizeSeed(baseSeed ?? seed);
  const project = getProject(projectName);
  if (!project.phases.includes(phase)) throw new Error(`${projectName} has no ${phase} phase`);
  const guidanceRuntime = guidance ? await enableGuidance(project.packageName, sourceDirectory) : undefined;
  const target = await project.createTarget(sourceDirectory);
  const startedAt = new Date().toISOString();
  const start = performance.now();
  const deadline = seconds === undefined ? Infinity : start + seconds * 1000;
  const prng = new PRNG(normalizedSeed);
  const coordinator = featureCoordinator(workerId);
  const corpus = new Corpus(corpusDirectory, phase, maxLength, project.validateCase);
  const coverage = guidance || (coverageEvery === undefined && coverageSeconds === undefined)
    ? undefined : new CoverageSampler(project.packageName, sourceDirectory);
  let runtimesClosed = false;
  const closeRuntimes = async (failed = false) => {
    if (runtimesClosed) return;
    runtimesClosed = true;
    try {
      if (coverage !== undefined) await coverage.close();
    } finally {
      coordinator.close(failed);
    }
  };
  const existing = await corpus.load();
  const features = new Set();
  const operations = Object.fromEntries(project.operations(phase).map((name) => [name, emptyOperationStats()]));
  const stats = {
    engine: 'noblefuzz',
    version: 2,
    project: projectName,
    phase,
    seed: normalizedSeed,
    baseSeed: normalizedBaseSeed,
    workerId: workerId ?? null,
    workerRole: guidance ? 'guidance' : 'throughput',
    maxLength,
    sourceDirectory: sourceDirectory ?? null,
    startedAt,
    runs: 0,
    initialCorpus: existing.length,
    importedCorpus: 0,
    coverageEvery: coverageEvery ?? null,
    coverageSeconds: coverageSeconds ?? null,
    coverageSamples: 0,
    coverageFeatures: 0,
    guidanceCases: 0,
    guidanceFeatures: 0,
    favoredRuns: 0,
    mutationSteps: 0,
    corpusEntries: 0,
    features: 0,
    elapsedSeconds: 0,
    sampledNanoseconds: 0,
    operations,
  };

  let coverageCounter = 0;
  let nextCoverageSample = start;
  const runOne = async (testcase, saveOnFeature = true, allowCoverage = false) => {
    project.validateCase(testcase, maxLength, phase);
    const operationStats = operations[testcase.operation];
    const sampleMask = project.sampleMask(phase);
    const coverageNow = allowCoverage && coverageSeconds !== undefined ? performance.now() : 0;
    const sampleByRuns = allowCoverage && coverageEvery !== undefined && coverageCounter++ % coverageEvery === 0;
    const sampleByTime = allowCoverage && coverageSeconds !== undefined && coverageNow >= nextCoverageSample;
    const sampleCoverage = allowCoverage && coverage !== undefined && (sampleByRuns || sampleByTime);
    if (sampleCoverage && coverageSeconds !== undefined) nextCoverageSample = coverageNow + coverageSeconds * 1000;
    const sample = !sampleCoverage && (operationStats.runs & sampleMask) === 0;
    const before = sample ? process.hrtime.bigint() : 0n;
    let result;
    let inspectorCoverage = [];
    let guidanceCoverage = [];
    const execute = () => {
      if (guidanceRuntime === undefined) return project.executeCase(target, testcase);
      guidanceRuntime.tracker.begin();
      try {
        return project.executeCase(target, testcase);
      } finally {
        guidanceCoverage = guidanceRuntime.tracker.finish();
      }
    };
    try {
      if (sampleCoverage) {
        const captured = await coverage.capture(execute);
        result = captured.value;
        inspectorCoverage = captured.features;
        stats.coverageSamples++;
      } else {
        result = execute();
      }
    } catch (error) {
      const filename = await saveFailure(
        artifactDirectory, phase, normalizedSeed, testcase, error, workerId, normalizedBaseSeed,
      );
      error.message = `${error.message}; reproducer: ${filename}`;
      await closeRuntimes(true);
      throw error;
    }
    if (sample) {
      const duration = Number(process.hrtime.bigint() - before);
      operationStats.sampledRuns++;
      operationStats.sampledNanoseconds += duration;
      stats.sampledNanoseconds += duration;
    }
    stats.runs++;
    operationStats.runs++;
    if (guidanceRuntime !== undefined) stats.guidanceCases++;
    const capturedCoverage = [...inspectorCoverage, ...guidanceCoverage];
    const names = caseFeatureNames(testcase, target, project, result, capturedCoverage);
    const newFeatures = addFeatures(features, names);
    corpus.setFeatures(testcase, names);
    const ownedFeatures = saveOnFeature ? await coordinator.claim(newFeatures) : [];
    if (saveOnFeature && ownedFeatures.length > 0) {
      const stored = capturedCoverage.length === 0 ? testcase : { ...testcase, coverage: capturedCoverage };
      await corpus.add(stored);
      corpus.setFeatures(stored, names);
    }
    return names;
  };

  if (bootstrap) {
    for (const testcase of existing) await runOne(testcase, false);
    for (const testcase of project.seedCases(phase, prng, target, maxLength)) {
      if (!corpus.hashes.has(createHash('sha256').update(encodeCase(testcase)).digest('hex'))) {
        const names = await runOne(testcase, false);
        await corpus.add(testcase);
        corpus.setFeatures(testcase, names);
      }
    }
  } else {
    for (const testcase of existing) {
      const names = caseFeatureNames(testcase, target, project);
      addFeatures(features, names);
      corpus.setFeatures(testcase, names);
    }
  }
  coordinator.sync([...features]);

  const desiredRuns = runLimit === undefined ? Infinity : stats.runs + runLimit;
  let nextStatus = start + 10_000;
  let nextYield = stats.runs + project.yieldInterval(phase);
  let nextCorpusRefresh = start + 1_000;
  let scheduledBase;
  let remainingEnergy = 0;

  while (performance.now() < deadline && stats.runs < desiredRuns) {
    let operation;
    let base;
    if (remainingEnergy > 0 && scheduledBase !== undefined) {
      operation = scheduledBase.operation;
      base = scheduledBase;
      remainingEnergy--;
      stats.favoredRuns++;
    } else {
      operation = project.chooseOperation(phase, prng);
      base = prng.bool(1, 5) ? undefined : corpus.pick(prng, operation);
      scheduledBase = base;
      remainingEnergy = base === undefined ? 0 : corpus.mutationEnergy(base) - 1;
    }
    let testcase;
    if (base === undefined) {
      testcase = project.generateCase(phase, prng, target, maxLength, operation);
    } else {
      testcase = base;
      const mutationDepth = prng.bool(1, 4) ? 2 + prng.int(3) : 1;
      for (let index = 0; index < mutationDepth; index++) {
        testcase = project.mutateCase(testcase, phase, prng, target, maxLength, corpus);
        delete testcase.coverage;
      }
      stats.mutationSteps += mutationDepth;
    }
    // Coverage belongs to the exact recorded input, not to its descendants.
    delete testcase.coverage;
    await runOne(testcase, true, true);

    if (stats.runs >= nextYield) {
      if (process.send !== undefined) {
        try {
          process.send({ type: 'heartbeat', phase, workerId, runs: stats.runs }, () => {});
        } catch (_) {
          // The supervisor may already be terminating the fleet.
        }
      }
      await yieldToEvents();
      nextYield = stats.runs + project.yieldInterval(phase);
    }
    const now = performance.now();
    if (now >= nextCorpusRefresh) {
      const imported = await corpus.refresh();
      stats.importedCorpus += imported.length;
      for (const testcase of imported) {
        const names = caseFeatureNames(testcase, target, project);
        addFeatures(features, names);
        corpus.setFeatures(testcase, names);
      }
      nextCorpusRefresh = now + 1_000;
    }
    if (!quiet && now >= nextStatus) {
      const elapsed = (now - start) / 1000;
      console.log(`# ${phase}: ${stats.runs} runs, ${(stats.runs / Math.max(elapsed, 0.001)).toFixed(0)}/s, ${features.size} features, ${corpus.entries.length} corpus`);
      nextStatus = now + 10_000;
    }
  }

  const finalImports = await corpus.refresh();
  stats.importedCorpus += finalImports.length;
  for (const testcase of finalImports) {
    const names = caseFeatureNames(testcase, target, project);
    addFeatures(features, names);
    corpus.setFeatures(testcase, names);
  }
  await closeRuntimes();
  stats.elapsedSeconds = (performance.now() - start) / 1000;
  stats.finishedAt = new Date().toISOString();
  stats.corpusEntries = corpus.entries.length;
  stats.features = features.size;
  stats.coverageFeatures = [...features].filter((feature) => feature.startsWith('v8:')).length;
  stats.guidanceFeatures = [...features].filter((feature) => feature.startsWith('js:')).length;
  const result = printableStats(stats);
  const transportResult = { ...result, featureNames: [...features].sort() };
  await mkdir(artifactDirectory, { recursive: true });
  const workerSuffix = workerId === undefined ? '' : `-worker-${workerId}`;
  await writeFile(path.join(artifactDirectory, `stats-${phase}${workerSuffix}.json`), `${JSON.stringify(result, null, 2)}\n`);
  if (!quiet) console.log(JSON.stringify(result));
  return transportResult;
}

export async function replayCases(options) {
  const project = getProject(options.project ?? 'noble-hashes');
  const target = await project.createTarget(options.sourceDirectory);
  let runs = 0;
  for (const testcase of options.cases) {
    project.validateCase(testcase, options.maxLength, options.phase);
    project.executeCase(target, testcase);
    runs++;
  }
  return runs;
}
