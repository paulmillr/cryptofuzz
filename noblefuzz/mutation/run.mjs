#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mutations, repositories } from './mutations.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(here, '..', '..');
const cli = path.join(repositoryRoot, 'noblefuzz', 'cli.mjs');

function argumentsMap(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!key?.startsWith('--') || argv[index + 1] === undefined) throw new Error(`invalid argument: ${key}`);
    result[key.slice(2)] = argv[index + 1];
  }
  return result;
}

function countOccurrences(source, value) {
  let count = 0;
  let offset = 0;
  while ((offset = source.indexOf(value, offset)) !== -1) {
    count++;
    offset += value.length;
  }
  return count;
}

function lastLines(value, maximum = 12) {
  return value.trim().split('\n').slice(-maximum).join('\n');
}

async function gitCommit(root) {
  const git = path.join(root, '.git');
  const head = (await readFile(path.join(git, 'HEAD'), 'utf8')).trim();
  if (!head.startsWith('ref: ')) return head;
  const reference = head.slice(5);
  try {
    return (await readFile(path.join(git, reference), 'utf8')).trim();
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const packed = await readFile(path.join(git, 'packed-refs'), 'utf8');
  const line = packed.split('\n').find((value) => value.endsWith(` ${reference}`));
  if (line === undefined) throw new Error(`cannot resolve Git reference ${reference}`);
  return line.split(' ')[0];
}

const args = argumentsMap(process.argv.slice(2));
if (args.root === undefined) throw new Error('usage: run.mjs --root <clone-parent> [--project noble-hashes] [--id mutation-id] [--output report.json]');
const cloneRoot = path.resolve(args.root);
const selected = mutations.filter((item) =>
  (args.project === undefined || item.project === args.project) && (args.id === undefined || item.id === args.id));
if (selected.length === 0) throw new Error(`no mutations selected for ${args.project}`);
const identities = new Set();
const classes = new Map();
for (const item of selected) {
  const identity = `${item.project}:${item.id}`;
  if (identities.has(identity)) throw new Error(`duplicate mutation id: ${identity}`);
  identities.add(identity);
  const projectClasses = classes.get(item.project) ?? new Set();
  if (projectClasses.has(item.defectClass)) throw new Error(`duplicate defect class in ${item.project}: ${item.defectClass}`);
  projectClasses.add(item.defectClass);
  classes.set(item.project, projectClasses);
}

const report = {
  version: 1,
  startedAt: new Date().toISOString(),
  cloneRoot,
  projects: {},
  baselines: [],
  mutations: [],
};
for (const project of new Set(selected.map((item) => item.project))) {
  const root = path.join(cloneRoot, repositories[project]);
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const commit = await gitCommit(root);
  report.projects[project] = { root, package: manifest.name, version: manifest.version, commit };
}

for (const item of selected) {
  const root = report.projects[item.project].root;
  const original = await readFile(path.join(root, item.file), 'utf8');
  const occurrences = countOccurrences(original, item.from);
  if (occurrences !== (item.occurrences ?? 1)) {
    throw new Error(`${item.project}/${item.id}: expected ${item.occurrences ?? 1} mutation site(s), found ${occurrences}`);
  }
}

const baselineSpecs = new Map();
for (const item of selected) {
  const maxLength = item.maxLength ?? (item.project === 'noble-post-quantum' ? 65536 : 4096);
  const timeoutSeconds = item.timeout ?? 30;
  const seed = item.seed ?? 0x4d555441;
  const key = `${item.project}:${item.phase}:${maxLength}:${timeoutSeconds}:${seed}`;
  baselineSpecs.set(key, { project: item.project, phase: item.phase, maxLength, timeoutSeconds, seed });
}
for (const spec of baselineSpecs.values()) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), `noblefuzz-baseline-${spec.project}-${spec.phase}-`));
  const corpus = path.join(temporary, 'corpus');
  const artifacts = path.join(temporary, 'artifacts');
  const started = Date.now();
  const execution = spawnSync(process.execPath, [cli, 'fuzz',
    '--project', spec.project,
    '--phase', spec.phase,
    '--runs', '1',
    '--seed', String(spec.seed),
    '--workers', '1',
    '--guidance-workers', '0',
    '--max-len', String(spec.maxLength),
    '--timeout', String(spec.timeoutSeconds),
    '--corpus', corpus,
    '--artifacts', artifacts,
    '--source-dir', report.projects[spec.project].root,
    '--quiet',
  ], { cwd: repositoryRoot, encoding: 'utf8', timeout: spec.timeoutSeconds * 1000 + 10_000 });
  const artifactFiles = await readdir(artifacts).catch(() => []);
  const passed = artifactFiles.every((name) => !name.startsWith('timeout-')) && execution.status === 0 &&
    execution.signal === null && execution.error?.code !== 'ETIMEDOUT';
  const result = {
    ...spec,
    passed,
    exitCode: execution.status,
    signal: execution.signal,
    spawnError: execution.error === undefined ? null : { code: execution.error.code, message: execution.error.message },
    elapsedMilliseconds: Date.now() - started,
    output: lastLines(`${execution.stdout ?? ''}\n${execution.stderr ?? ''}`),
  };
  report.baselines.push(result);
  console.log(`[baseline] ${passed ? 'PASSED' : 'FAILED'} ${spec.project}/${spec.phase} (${result.elapsedMilliseconds} ms)`);
  await rm(temporary, { recursive: true, force: true });
  if (!passed) throw new Error(`clean baseline failed for ${spec.project}/${spec.phase}:\n${result.output}`);
}

for (const [index, item] of selected.entries()) {
  const root = report.projects[item.project].root;
  const original = await readFile(path.join(root, item.file), 'utf8');
  const occurrences = countOccurrences(original, item.from);
  if (occurrences !== (item.occurrences ?? 1)) {
    throw new Error(`${item.project}/${item.id}: expected ${item.occurrences ?? 1} mutation site(s), found ${occurrences}`);
  }
  const mutated = (item.occurrences ?? 1) === 1
    ? original.replace(item.from, item.to)
    : original.replaceAll(item.from, item.to);
  const temporary = await mkdtemp(path.join(os.tmpdir(), `noblefuzz-${item.id}-`));
  const sourceRoot = path.join(temporary, 'source');
  const excludedRoots = new Set(['.git', '.github', 'benchmark', 'node_modules', 'scripts', 'src', 'test']);
  await cp(root, sourceRoot, {
    recursive: true,
    filter(source) {
      const relative = path.relative(root, source);
      return relative === '' || !excludedRoots.has(relative.split(path.sep)[0]);
    },
  });
  await symlink(path.join(root, 'node_modules'), path.join(sourceRoot, 'node_modules'), 'dir');
  const filename = path.join(sourceRoot, item.file);
  const corpus = path.join(temporary, 'corpus');
  const artifacts = path.join(temporary, 'artifacts');
  const maxLength = item.maxLength ?? (item.project === 'noble-post-quantum' ? 65536 : 4096);
  const timeoutSeconds = item.timeout ?? 30;
  const started = Date.now();
  let execution;
  await writeFile(filename, mutated);
  const syntax = spawnSync(process.execPath, ['--check', filename], { encoding: 'utf8' });
  if (syntax.status !== 0) throw new Error(`${item.id} produced invalid JavaScript:\n${syntax.stderr}`);
  execution = spawnSync(process.execPath, [cli, 'fuzz',
      '--project', item.project,
      '--phase', item.phase,
      '--runs', String(item.runs ?? 1),
      '--seed', String(item.seed ?? 0x4d555441),
      '--workers', '1',
      '--guidance-workers', '0',
      '--max-len', String(maxLength),
      '--timeout', String(timeoutSeconds),
      '--corpus', corpus,
      '--artifacts', artifacts,
      '--source-dir', sourceRoot,
      '--quiet',
    ], { cwd: repositoryRoot, encoding: 'utf8', timeout: timeoutSeconds * 1000 + 10_000 });
  const artifactFiles = await readdir(artifacts).catch(() => []);
  const failureReports = artifactFiles.filter((name) => name.endsWith('.report.json'));
  const timeoutReports = artifactFiles.filter((name) => name.startsWith('timeout-'));
  const detected = timeoutReports.length === 0 && execution.status !== null && execution.status !== 0 &&
    execution.signal === null && execution.error?.code !== 'ETIMEDOUT';
  const result = {
    project: item.project,
    id: item.id,
    defectClass: item.defectClass,
    file: item.file,
    phase: item.phase,
    detected,
    detection: detected ? (failureReports.length > 0 ? 'testcase' : 'startup') : 'survived',
    exitCode: execution.status,
    signal: execution.signal,
    spawnError: execution.error === undefined ? null : { code: execution.error.code, message: execution.error.message },
    elapsedMilliseconds: Date.now() - started,
    failureReports,
    timeoutReports,
    output: lastLines(`${execution.stdout ?? ''}\n${execution.stderr ?? ''}`),
  };
  report.mutations.push(result);
  console.log(`[${index + 1}/${selected.length}] ${detected ? 'DETECTED' : 'SURVIVED'} ${item.project}/${item.id} (${result.elapsedMilliseconds} ms)`);
  await rm(temporary, { recursive: true, force: true });
}

report.finishedAt = new Date().toISOString();
report.summary = {};
for (const project of Object.keys(report.projects)) {
  const values = report.mutations.filter((item) => item.project === project);
  report.summary[project] = {
    total: values.length,
    detected: values.filter((item) => item.detected).length,
    survived: values.filter((item) => !item.detected).length,
    defectClasses: new Set(values.map((item) => item.defectClass)).size,
  };
}
const output = path.resolve(args.output ?? path.join(repositoryRoot, 'noblefuzz', 'mutation-report.json'));
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(`wrote ${output}`);
if (Object.values(report.summary).some((value) => value.detected < 15 || value.defectClasses < 15 || value.survived !== 0)) {
  process.exitCode = 1;
}
