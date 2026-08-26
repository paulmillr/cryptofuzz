import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CIPHER_SPECS } from './lib/projects/ciphers-target.mjs';
import { ciphersProject } from './lib/projects/ciphers.mjs';
import { FIELD_CALC_OPERATIONS, createCurvesTarget } from './lib/projects/curves-target.mjs';
import { CURVE_FAST_OPERATIONS, CURVE_PAIRING_OPERATIONS } from './lib/projects/curves.mjs';
import { createPostQuantumTarget } from './lib/projects/post-quantum-target.mjs';
import { postQuantumProject } from './lib/projects/post-quantum.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = async (relative) => readFile(path.join(root, relative), 'utf8');
const sorted = (values) => [...new Set(values)].sort();
const matches = (text, expression) => [...text.matchAll(expression)].map((match) => match[1]);
const assertSet = (actual, expected, label) => assert.deepEqual(sorted(actual), sorted(expected), label);

const cipherTest = await source('modules/noble-ciphers/test.mjs');
const supportedStart = cipherTest.indexOf('const supported = [');
const supportedBlock = cipherTest.slice(supportedStart, cipherTest.indexOf('];', supportedStart));
const cipherNames = matches(supportedBlock, /\['([A-Z0-9_]+)'/g);
assertSet(CIPHER_SPECS.map((spec) => spec.name), cipherNames, 'noblefuzz cipher identifiers drifted from the adapter');
assertSet(ciphersProject.operations('ciphers'), ['SymmetricEncrypt', 'SymmetricDecrypt'], 'cipher operations drifted');

const curveHarness = await source('modules/noble-curves/harness.js');
const curveDispatch = curveHarness.slice(curveHarness.indexOf('const input ='));
const curveOperations = matches(curveDispatch, /ids\.Is([A-Za-z0-9_]+)\(operation\)/g);
assertSet([...CURVE_FAST_OPERATIONS, ...CURVE_PAIRING_OPERATIONS], curveOperations, 'curve operations drifted');
const fieldStart = curveHarness.indexOf('function OpBignumCalc');
const fieldBlock = curveHarness.slice(fieldStart, curveHarness.indexOf('const input =', fieldStart));
assertSet(FIELD_CALC_OPERATIONS, matches(fieldBlock, /ids\.Is([A-Za-z0-9_]+)\(operation\)/g), 'field sub-operations drifted');
const curveInfoStart = curveHarness.indexOf('function curveInfo');
const curveInfo = curveHarness.slice(curveInfoStart, curveHarness.indexOf('function signingCurve', curveInfoStart));
const pairingStart = curveHarness.indexOf('function pairingCurve');
const pairingInfo = curveHarness.slice(pairingStart, curveHarness.indexOf('function dstBytes', pairingStart));
const curvesTarget = await createCurvesTarget();
assertSet(curvesTarget.descriptors.map((info) => info.name),
  matches(curveInfo, /ids\.Is([A-Za-z0-9_]+)\(id\)/g), 'curve identifiers drifted');
assertSet(curvesTarget.pairing.keys(), matches(pairingInfo, /ids\.Is([A-Za-z0-9_]+)\(id\)/g), 'pairing identifiers drifted');

const pqHarness = await source('modules/noble-post-quantum/harness.js');
const pqIdentifiers = matches(pqHarness,
  /ids\.Is((?:ML_KEM|KitchenSink|QSF|X_Wing|ML_DSA|SLH_DSA|Falcon)[A-Za-z0-9_]*)\(id\)/g);
const pqTarget = await createPostQuantumTarget();
assertSet(pqTarget.descriptors.map((info) => info.name), pqIdentifiers, 'post-quantum identifiers drifted');
assertSet(postQuantumProject.operations('general'),
  ['KEM_KeyGen', 'KEM_Encapsulate', 'KEM_Decapsulate', 'PQSIG_KeyGen', 'PQSIG_Sign', 'PQSIG_Verify'],
  'post-quantum general operations drifted');
assertSet(postQuantumProject.operations('slh-dsa'), ['PQSIG_KeyGen', 'PQSIG_Sign', 'PQSIG_Verify'],
  'post-quantum SLH-DSA operations drifted');

const packageManifest = JSON.parse(await source('noblefuzz/package.json'));
const independentOracles = [
  'tiny-secp256k1', 'mcl-wasm', 'ffjavascript', '@oqs/liboqs-js',
  '@stablelib/aes', '@stablelib/salsa20', '@stablelib/siv', '@stablelib/xchacha20poly1305',
];
for (const packageName of independentOracles) {
  assert.equal(typeof packageManifest.dependencies[packageName], 'string', `${packageName} is not pinned`);
  const oracleManifest = JSON.parse(await source(`noblefuzz/node_modules/${packageName}/package.json`));
  const dependencies = {
    ...oracleManifest.dependencies,
    ...oracleManifest.optionalDependencies,
    ...oracleManifest.peerDependencies,
  };
  assert.equal(Object.keys(dependencies).some((name) => name.startsWith('@noble/')), false,
    `${packageName} is not independent from Noble`);
}

console.log('noblefuzz adapter-contract audit passed');
