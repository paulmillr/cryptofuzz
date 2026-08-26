#!/usr/bin/env node

import { appendFile, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

async function manifest(directory) {
  return JSON.parse(await readFile(path.join(await realpath(directory), 'package.json'), 'utf8'));
}

const projectName = process.env.PROJECT_NAME;
const projects = new Map([
  ['noble-hashes', { packageName: '@noble/hashes', maxLength: 4096 }],
  ['noble-ciphers', { packageName: '@noble/ciphers', maxLength: 4096 }],
  ['noble-curves', { packageName: '@noble/curves', maxLength: 4096 }],
  ['noble-post-quantum', { packageName: '@noble/post-quantum', maxLength: 65536 }],
]);
const selected = projects.get(projectName);
if (selected === undefined) throw new Error(`noblefuzz does not support ${JSON.stringify(projectName)}`);
if (!process.env.NOBLE_SOURCE_ROOT) throw new Error('NOBLE_SOURCE_ROOT is required');
if (!process.env.NOBLEFUZZ_ROOT) throw new Error('NOBLEFUZZ_ROOT is required');
if (!process.env.GITHUB_OUTPUT) throw new Error('GITHUB_OUTPUT is required');

const source = await manifest(process.env.NOBLE_SOURCE_ROOT);
if (source.name !== selected.packageName) {
  throw new Error(`caller package must be ${selected.packageName}, got ${JSON.stringify(source.name)}`);
}
const engine = await manifest(process.env.NOBLEFUZZ_ROOT);
if (engine.name !== 'noblefuzz' || engine.dependencies?.[selected.packageName] === undefined) {
  throw new Error(`noblefuzz must have a pinned ${selected.packageName} dependency`);
}

await appendFile(process.env.GITHUB_OUTPUT,
  `module=${projectName}\nsource_package=${selected.packageName}\nmax_len=${selected.maxLength}\n`);
console.log(`Selected noblefuzz for ${selected.packageName}`);
