#!/usr/bin/env node

import { fork } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeCase, encodeCase } from './lib/cases.mjs';
import { Corpus } from './lib/corpus.mjs';
import { replayCases, runEngine } from './lib/engine.mjs';
import { getProject } from './lib/projects/index.mjs';
import { minimizeFailure, reduceCorpus } from './lib/reducer.mjs';
import { normalizeSeed } from './lib/seed.mjs';
import { mergeWorkerStats } from './lib/stats.mjs';
import { deriveWorkerSeed, resolveWorkerCount } from './lib/workers.mjs';

const self = fileURLToPath(import.meta.url);

function parseArguments(argv) {
  const values = { _: [] };
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      values._.push(argument);
      continue;
    }
    const equals = argument.indexOf('=');
    if (equals !== -1) {
      values[argument.slice(2, equals)] = argument.slice(equals + 1);
    } else if (argv[index + 1] !== undefined && !argv[index + 1].startsWith('--')) {
      values[argument.slice(2)] = argv[++index];
    } else {
      values[argument.slice(2)] = true;
    }
  }
  return values;
}

function integerArgument(args, name, { minimum = 1, optional = false } = {}) {
  if (args[name] === undefined && optional) return undefined;
  const value = Number(args[name]);
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`--${name} must be an integer >= ${minimum}`);
  return value;
}

function environmentInteger(name, { minimum = 1, optional = false } = {}) {
  const value = process.env[name];
  if (value === undefined && optional) return undefined;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return number;
}

function environmentFlag(name, defaultValue = false) {
  const value = process.env[name];
  if (value === undefined) return defaultValue;
  if (value === '1') return true;
  if (value === '0') return false;
  throw new Error(`${name} must be 0 or 1`);
}

function seedValue(value, label) {
  try {
    return normalizeSeed(value);
  } catch (error) {
    throw new Error(`${label}: ${error.message}`);
  }
}

function engineOptions(args, engineChild = false) {
  const phase = args.phase;
  if (typeof phase !== 'string' || phase.length === 0) throw new Error('--phase is required');
  const seconds = integerArgument(args, 'seconds', { optional: true });
  const requestedRuns = integerArgument(args, 'runs', { optional: true });
  const runs = engineChild
    ? environmentInteger('NOBLEFUZZ_ENGINE_RUNS', { optional: true }) ?? requestedRuns
    : requestedRuns;
  if (seconds === undefined && runs === undefined) throw new Error('one of --seconds or --runs is required');
  const baseSeed = seedValue(args.seed, '--seed');
  const coverageEvery = integerArgument(args, 'coverage-every', { optional: true });
  const coverageSeconds = integerArgument(args, 'coverage-seconds', { optional: true });
  if (coverageEvery !== undefined && coverageSeconds !== undefined) {
    throw new Error('use only one of --coverage-every or --coverage-seconds');
  }
  return {
    project: String(args.project ?? process.env.NOBLE_PROJECT ?? 'noble-hashes'),
    phase,
    seconds,
    runs,
    seed: engineChild ? seedValue(process.env.NOBLEFUZZ_ENGINE_SEED, 'NOBLEFUZZ_ENGINE_SEED') : baseSeed,
    baseSeed,
    workerId: engineChild ? environmentInteger('NOBLEFUZZ_ENGINE_WORKER_ID', { minimum: 0 }) : undefined,
    maxLength: integerArgument(args, 'max-len', { minimum: 16 }),
    corpusDirectory: path.resolve(String(args.corpus ?? `fuzz-corpus-${phase}`)),
    artifactDirectory: path.resolve(String(args.artifacts ?? 'fuzz-artifacts')),
    sourceDirectory: args['source-dir'] ?? process.env.NOBLE_SOURCE_DIR,
    quiet: engineChild || args.quiet === true,
    bootstrap: engineChild ? environmentFlag('NOBLEFUZZ_ENGINE_BOOTSTRAP', true) : true,
    coverageEvery,
    coverageSeconds,
    guidance: engineChild ? environmentFlag('NOBLEFUZZ_ENGINE_GUIDANCE', false) : false,
  };
}

async function supervise(args) {
  const options = engineOptions(args);
  const timeout = integerArgument(args, 'timeout');
  const workerSpec = args.workers ?? process.env.NOBLEFUZZ_WORKERS ?? 1;
  let workerCount = resolveWorkerCount(workerSpec);
  if (options.runs !== undefined) workerCount = Math.min(workerCount, options.runs);
  const guidanceWorkers = integerArgument(args, 'guidance-workers', { minimum: 0, optional: true }) ?? 0;
  if (guidanceWorkers > workerCount) throw new Error('--guidance-workers cannot exceed the resolved worker count');
  await mkdir(options.artifactDirectory, { recursive: true });
  const childArguments = process.argv.slice(2).filter((argument) => argument !== '--engine-child');
  childArguments.push('--engine-child');
  const started = Date.now();
  const states = [];
  let resolveFleet;
  let rejectFleet;
  let failureStarted = false;
  let completed = 0;
  const claimedFeatures = new Set();
  const fleet = new Promise((resolve, reject) => {
    resolveFleet = resolve;
    rejectFleet = reject;
  });

  const killFleet = (signal = 'SIGKILL') => {
    for (const state of states) {
      if (!state.exited) state.child.kill(signal);
    }
  };
  const failWorker = async (state, { code = null, signal = null, timedOut = false, message }) => {
    if (failureStarted) return;
    failureStarted = true;
    killFleet();
    const kind = timedOut ? 'timeout' : 'process-failure';
    const report = {
      phase: options.phase,
      seed: options.seed,
      workerSeed: state.seed,
      workerId: state.id,
      workers: workerCount,
      timeoutSeconds: timeout,
      exitCode: code,
      signal,
      lastHeartbeatRuns: state.runs,
      message,
    };
    const filename = path.join(options.artifactDirectory, `${kind}-${options.phase}-worker-${state.id}.json`);
    let reportError;
    try {
      await writeFile(filename, `${JSON.stringify(report, null, 2)}\n`);
    } catch (error) {
      reportError = error;
    }
    const cause = signal ?? (code === null ? message : `exit ${code}`);
    const suffix = reportError === undefined ? '' : `; could not write failure report: ${reportError.message}`;
    rejectFleet(new Error(`noblefuzz ${options.phase} worker ${state.id} failed (${cause})${suffix}`));
  };

  for (let workerId = 0; workerId < workerCount; workerId++) {
    const workerSeed = deriveWorkerSeed(options.seed, workerId, `${options.project}/${options.phase}`);
    const workerRuns = options.runs === undefined
      ? undefined
      : Math.floor(options.runs / workerCount) + (workerId < options.runs % workerCount ? 1 : 0);
    const env = {
      ...process.env,
      NOBLEFUZZ_ENGINE_WORKER_ID: String(workerId),
      NOBLEFUZZ_ENGINE_SEED: String(workerSeed),
      NOBLEFUZZ_ENGINE_BOOTSTRAP: workerId === 0 ? '1' : '0',
      NOBLEFUZZ_ENGINE_GUIDANCE: workerId < guidanceWorkers ? '1' : '0',
    };
    if (workerRuns !== undefined) env.NOBLEFUZZ_ENGINE_RUNS = String(workerRuns);
    else delete env.NOBLEFUZZ_ENGINE_RUNS;
    const child = fork(self, childArguments, { env, stdio: ['inherit', 'inherit', 'inherit', 'ipc'] });
    const state = { id: workerId, seed: workerSeed, child, lastHeartbeat: Date.now(), runs: 0, result: undefined, exited: false };
    states.push(state);
    child.on('message', (message) => {
      if (message?.workerId !== workerId) return;
      if (message.type === 'heartbeat') {
        state.lastHeartbeat = Date.now();
        state.runs = message.runs;
      } else if (message.type === 'result') {
        state.lastHeartbeat = Date.now();
        state.runs = message.result.runs;
        state.result = message.result;
      } else if (message.type === 'feature-sync' && Array.isArray(message.features)) {
        for (const feature of message.features) claimedFeatures.add(feature);
      } else if (message.type === 'feature-claim' && Array.isArray(message.features)) {
        const accepted = [];
        for (const feature of message.features) {
          if (claimedFeatures.has(feature)) continue;
          claimedFeatures.add(feature);
          accepted.push(feature);
        }
        try {
          child.send({ type: 'feature-claim-result', requestId: message.requestId, accepted }, () => {});
        } catch (_) {
          // A failing worker may close IPC while its final claim is in flight.
        }
      }
    });
    child.once('error', (error) => {
      void failWorker(state, { message: error.message });
    });
    child.once('exit', (code, signal) => {
      state.exited = true;
      if (failureStarted) return;
      if (code !== 0 || signal !== null) {
        void failWorker(state, { code, signal, message: 'worker exited without completing the phase' });
      } else if (state.result === undefined) {
        void failWorker(state, { code, signal, message: 'worker exited without reporting its result' });
      } else {
        completed++;
        if (completed === workerCount) resolveFleet();
      }
    });
  }

  const watchdog = setInterval(() => {
    const now = Date.now();
    for (const state of states) {
      if (!state.exited && now - state.lastHeartbeat > timeout * 1000) {
        void failWorker(state, { timedOut: true, message: 'worker stopped making progress' });
        break;
      }
    }
  }, Math.min(1000, timeout * 250));
  const status = setInterval(() => {
    if (options.quiet) return;
    const runs = states.reduce((sum, state) => sum + state.runs, 0);
    const elapsed = (Date.now() - started) / 1000;
    console.log(`# ${options.phase}: ${runs} runs, ${(runs / Math.max(elapsed, 0.001)).toFixed(0)}/s, ${workerCount} workers`);
  }, 10_000);
  const forward = (signal) => killFleet(signal);
  process.once('SIGINT', forward);
  process.once('SIGTERM', forward);
  try {
    await fleet;
  } finally {
    clearInterval(watchdog);
    clearInterval(status);
    process.removeListener('SIGINT', forward);
    process.removeListener('SIGTERM', forward);
  }

  const corpusEntries = (await readdir(options.corpusDirectory)).filter((name) => name.endsWith('.json')).length;
  const result = mergeWorkerStats(states.map((state) => state.result), {
    seed: options.seed,
    corpusEntries,
  });
  result.guidanceWorkers = guidanceWorkers;
  await writeFile(path.join(options.artifactDirectory, `stats-${options.phase}.json`), `${JSON.stringify(result, null, 2)}\n`);
  if (!options.quiet) console.log(JSON.stringify(result));
  return result;
}

async function replay(args) {
  if (args._.length === 0) throw new Error('replay requires one or more testcase files or directories');
  const filenames = await collectCaseFilenames(args._);
  const cases = [];
  for (const filename of filenames) cases.push(decodeCase(await readFile(filename, 'utf8')));
  const count = await replayCases({
    cases,
    project: String(args.project ?? process.env.NOBLE_PROJECT ?? 'noble-hashes'),
    phase: args.phase,
    maxLength: integerArgument(args, 'max-len'),
    sourceDirectory: args['source-dir'] ?? process.env.NOBLE_SOURCE_DIR,
  });
  console.log(`Replayed ${count} testcase(s)`);
}

async function collectCaseFilenames(values) {
  const filenames = [];
  for (const value of values) {
    const filename = path.resolve(value);
    const stat = await import('node:fs/promises').then(({ stat }) => stat(filename));
    if (stat.isDirectory()) {
      for (const child of (await readdir(filename)).filter((name) => name.endsWith('.json')).sort()) {
        if (!child.endsWith('.report.json')) filenames.push(path.join(filename, child));
      }
    } else {
      filenames.push(filename);
    }
  }
  return filenames;
}

function maintenanceOptions(args) {
  const projectName = String(args.project ?? process.env.NOBLE_PROJECT ?? 'noble-hashes');
  const phase = args.phase;
  if (typeof phase !== 'string' || phase.length === 0) throw new Error('--phase is required');
  return {
    projectName,
    project: getProject(projectName),
    phase,
    maxLength: integerArgument(args, 'max-len'),
    sourceDirectory: args['source-dir'] ?? process.env.NOBLE_SOURCE_DIR,
  };
}

async function minimize(args) {
  if (args._.length !== 1) throw new Error('minimize requires exactly one failing testcase');
  const options = maintenanceOptions(args);
  const input = path.resolve(args._[0]);
  const output = path.resolve(String(args.output ?? input.replace(/\.json$/, '') + '.min.json'));
  if (output === input) throw new Error('minimized output must differ from its input');
  const testcase = decodeCase(await readFile(input, 'utf8'));
  const target = await options.project.createTarget(options.sourceDirectory);
  const result = minimizeFailure(options.project, target, testcase, options.maxLength, options.phase);
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, encodeCase(result.testcase), { flag: 'wx' });
  console.log(JSON.stringify({ ...result, testcase: undefined, input, output }));
}

async function reduceCorpusCommand(args) {
  if (args._.length === 0) throw new Error('reduce-corpus requires one or more corpus files or directories');
  if (typeof args.output !== 'string') throw new Error('reduce-corpus requires --output');
  const options = maintenanceOptions(args);
  const output = path.resolve(args.output);
  const filenames = await collectCaseFilenames(args._);
  const cases = [];
  for (const filename of filenames) cases.push(decodeCase(await readFile(filename, 'utf8')));
  const target = await options.project.createTarget(options.sourceDirectory);
  const result = reduceCorpus(options.project, target, cases, options.maxLength, options.phase);
  const corpus = new Corpus(output, options.phase, options.maxLength, options.project.validateCase);
  if ((await corpus.load()).length !== 0) throw new Error(`output corpus is not empty: ${output}`);
  for (const testcase of result.cases) await corpus.add(testcase);
  console.log(JSON.stringify({ ...result, cases: undefined, output }));
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArguments(rest);
  if (command === 'fuzz') {
    if (args['engine-child']) {
      const options = engineOptions(args, true);
      const result = await runEngine(options);
      if (process.send !== undefined) {
        await new Promise((resolve, reject) => {
          process.send({ type: 'result', workerId: options.workerId, result }, (error) => error ? reject(error) : resolve());
        });
      }
    } else {
      await supervise(args);
    }
  } else if (command === 'replay') {
    await replay(args);
  } else if (command === 'minimize') {
    await minimize(args);
  } else if (command === 'reduce-corpus') {
    await reduceCorpusCommand(args);
  } else {
    throw new Error('usage: noblefuzz/cli.mjs fuzz|replay|minimize|reduce-corpus [options]');
  }
}

main().catch((error) => {
  console.error(error.stack ?? error);
  // Engine children use an IPC channel for feature coordination. Construction/seed-generation
  // failures can happen before runEngine's local cleanup path; disconnect here as the final guard
  // so a failed child exits immediately instead of waiting for the supervisor watchdog.
  if (process.connected) process.disconnect();
  process.exitCode = 1;
});
