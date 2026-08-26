#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const argv = process.argv.slice(2);
const outputIndex = argv.indexOf('--output');
let output = path.resolve('noblefuzz/mutation-report.md');
if (outputIndex !== -1) {
  if (argv[outputIndex + 1] === undefined) throw new Error('--output requires a filename');
  output = path.resolve(argv[outputIndex + 1]);
  argv.splice(outputIndex, 2);
}
if (argv.length === 0) throw new Error('usage: report.mjs [--output report.md] report.json [...]');

const reports = await Promise.all(argv.map(async (filename) => JSON.parse(await readFile(filename, 'utf8'))));
const projects = Object.assign({}, ...reports.map((report) => report.projects));
const baselines = reports.flatMap((report) => report.baselines ?? []);
const mutationMap = new Map();
for (const report of reports) {
  for (const item of report.mutations) mutationMap.set(`${item.project}:${item.id}`, item);
}
const mutations = [...mutationMap.values()];
const escape = (value) => String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
const lines = [
  '# noblefuzz mutation campaign',
  '',
  `Generated from ${reports.length} machine-readable report${reports.length === 1 ? '' : 's'}. A mutation counts only when the fuzzer exits on a concrete startup or testcase failure; watchdog and process timeouts are not credited.`,
  '',
  '## Clean baselines',
  '',
  '| Project | Phase | Seed | Result |',
  '| --- | --- | ---: | --- |',
  ...baselines.map((item) => `| ${escape(item.project)} | ${escape(item.phase)} | ${item.seed} | ${item.passed ? 'passed' : 'failed'} |`),
  '',
  '## Mutation score',
  '',
  '| Project | Version | Commit | Detected | Distinct classes | Survived |',
  '| --- | --- | --- | ---: | ---: | ---: |',
];
let totalDetected = 0;
let totalSurvived = 0;
for (const project of Object.keys(projects).sort()) {
  const values = mutations.filter((item) => item.project === project);
  const detected = values.filter((item) => item.detected).length;
  const survived = values.length - detected;
  const classes = new Set(values.map((item) => item.defectClass)).size;
  totalDetected += detected;
  totalSurvived += survived;
  const metadata = projects[project];
  lines.push(`| ${escape(project)} | ${escape(metadata.version)} | \`${escape(metadata.commit)}\` | ${detected}/${values.length} | ${classes} | ${survived} |`);
}
lines.push('', `Total: **${totalDetected}/${mutations.length} detected**, ${totalSurvived} survived.`, '');

for (const project of Object.keys(projects).sort()) {
  lines.push(`## ${project}`, '', '| Mutation | Defect class | Phase | Detection |', '| --- | --- | --- | --- |');
  for (const item of mutations.filter((value) => value.project === project)) {
    lines.push(`| \`${escape(item.id)}\` | ${escape(item.defectClass)} | ${escape(item.phase)} | ${escape(item.detection)} |`);
  }
  lines.push('');
}

await writeFile(output, `${lines.join('\n')}\n`);
console.log(`wrote ${output}`);
