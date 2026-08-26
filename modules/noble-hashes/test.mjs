import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-hashes.js', import.meta.url), 'utf8');
const idSource = fs.readFileSync(new URL('./ids.js', import.meta.url), 'utf8');
const ids = Object.fromEntries(
  [...idSource.matchAll(/export const Is(\w+) = function\(id\) \{ return id === "(\d+)"; \}/g)]
    .map((match) => [match[1], match[2]])
);

function run(operation, input) {
  const context = {
    FuzzerInput: JSON.stringify({ ...input, operation: ids[operation] }),
    FuzzerOutput: undefined,
  };
  vm.runInNewContext(bundle, context);
  return context.FuzzerOutput === undefined ? undefined : JSON.parse(context.FuzzerOutput);
}

const directContext = {};
vm.runInNewContext(bundle, directContext);

function arrayBufferFromHex(hex) {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16)).buffer;
}

function runDirectDigest(digestType, multipart, parts) {
  const result = directContext.CryptofuzzDigest(
    digestType,
    multipart ? '1' : '0',
    parts.map(arrayBufferFromHex)
  );
  return result === undefined ? undefined : Buffer.from(result).toString('hex');
}

function runNodeRequest(body) {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32LE(body.length);
  const worker = spawnSync(process.execPath, ['node-worker.mjs'], {
    input: Buffer.concat([header, body, Buffer.alloc(4)]),
    maxBuffer: 1024 * 1024,
  });
  assert.equal(worker.status, 0, worker.stderr.toString());
  assert.ok(worker.stdout.length >= 11);
  const responseSize = worker.stdout.readUInt32LE();
  assert.equal(responseSize, worker.stdout.length - 4);
  let offset = 4;
  assert.equal(worker.stdout[offset++], 1);
  const outputSize = worker.stdout.readUInt32LE(offset);
  offset += 4;
  const output = worker.stdout.subarray(offset, offset + outputSize);
  offset += outputSize;
  const coverageCount = worker.stdout.readUInt16LE(offset);
  assert.ok(coverageCount > 0);
  assert.equal(offset + 2 + coverageCount * 3, worker.stdout.length);
  return output;
}

function runNodeDigest(digestType, multipart, parts) {
  const bodySize = 14 + parts.reduce((size, part) => size + 4 + part.length / 2, 0);
  const body = Buffer.allocUnsafe(bodySize);
  let offset = 0;
  body[offset++] = 0;
  body.writeBigUInt64LE(BigInt(digestType), offset);
  offset += 8;
  body[offset++] = multipart ? 1 : 0;
  body.writeUInt32LE(parts.length, offset);
  offset += 4;
  for (const part of parts) {
    const bytes = Buffer.from(part, 'hex');
    body.writeUInt32LE(bytes.length, offset);
    offset += 4;
    bytes.copy(body, offset);
    offset += bytes.length;
  }
  return runNodeRequest(body).toString('hex');
}

function runNodeJSON(operation, input) {
  const json = Buffer.from(JSON.stringify({ ...input, operation: ids[operation] }));
  const body = Buffer.allocUnsafe(json.length + 1);
  body[0] = 1;
  json.copy(body, 1);
  return JSON.parse(runNodeRequest(body).toString());
}

assert.equal(run('Digest', {
  digestType: ids.SHA256,
  haveParts: false,
  cleartext: '',
}), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

assert.equal(run('Digest', {
  digestType: ids.SHA256,
  haveParts: true,
  cleartext: '616263',
  parts: ['61', '', '6263'],
}), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

assert.equal(
  runDirectDigest(ids.SHA256, false, ['616263']),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
);
assert.equal(
  runDirectDigest(ids.SHA256, true, ['61', '', '6263']),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
);
assert.equal(
  runNodeDigest(ids.SHA256, true, ['61', '', '6263']),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
);

assert.equal(run('HMAC', {
  digestType: ids.SHA256,
  haveParts: false,
  cleartext: '4869205468657265',
  cipher: { key: '0b'.repeat(20) },
}), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

assert.equal(run('KDF_HKDF', {
  digestType: ids.SHA256,
  password: '0b'.repeat(22),
  salt: '000102030405060708090a0b0c',
  info: 'f0f1f2f3f4f5f6f7f8f9',
  keySize: '42',
}), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

assert.equal(runNodeJSON('KDF_HKDF', {
  digestType: ids.SHA256,
  password: '0b'.repeat(22),
  salt: '000102030405060708090a0b0c',
  info: 'f0f1f2f3f4f5f6f7f8f9',
  keySize: '42',
}), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

assert.equal(run('KDF_PBKDF2', {
  digestType: ids.SHA256,
  password: '70617373776f7264',
  salt: '73616c74',
  iterations: '1',
  keySize: '32',
}), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');

assert.equal(run('Digest', {
  digestType: ids.SHA512_256,
  haveParts: false,
  cleartext: '616263',
}), '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23');

assert.equal(run('Digest', {
  digestType: ids.BLAKE2B256,
  haveParts: true,
  cleartext: '616263',
  parts: ['61', '6263'],
}), 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');

assert.equal(run('Digest', {
  digestType: ids.BLAKE2S128,
  haveParts: false,
  cleartext: '616263',
}), 'aa4938119b1dc7b87cbad0ffd200d0ae');

const shake128Digest = run('Digest', {
  digestType: ids.SHAKE128,
  haveParts: false,
  cleartext: '616263',
});
assert.equal(shake128Digest, '5881092dd818bf5cf8a3ddb793fbcba7');
assert.equal(shake128Digest.length, 16 * 2);

const shake256Digest = run('Digest', {
  digestType: ids.SHAKE256,
  haveParts: false,
  cleartext: '616263',
});
assert.equal(shake256Digest, '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739');
assert.equal(shake256Digest.length, 32 * 2);

const shake128Hmac = run('HMAC', {
  digestType: ids.SHAKE128,
  haveParts: false,
  cleartext: '616263',
  cipher: { key: '000102030405060708090a0b0c0d0e0f' },
});
assert.equal(shake128Hmac, 'ec6c3c3866d69009df19700704ece528eadccb1ca2518acdc0ddb3862b737ad7');
assert.equal(shake128Hmac.length, 32 * 2);

const shake256Hmac = run('HMAC', {
  digestType: ids.SHAKE256,
  haveParts: false,
  cleartext: '616263',
  cipher: { key: '000102030405060708090a0b0c0d0e0f' },
});
assert.equal(shake256Hmac, 'c104379513fcede142e5cde90d0392061cb66aea2b7cd7215be9ddd4dbdff13becfe96638cb7c9d3a6b8b4385c4bcee84f5a2b4e94bfa870a836143581c3df14');
assert.equal(shake256Hmac.length, 64 * 2);

assert.equal(run('KDF_HKDF', {
  digestType: ids.SHAKE128,
  password: '0b'.repeat(22),
  salt: '000102030405060708090a0b0c',
  info: 'f0f1f2f3f4f5f6f7f8f9',
  keySize: '42',
}), '912a8c5d510bcbd13658c5c6adce81b6b566ad992e047fdb89ad14107b7ec912b9c2f3a794af9e6b758e');

assert.equal(run('KDF_HKDF', {
  digestType: ids.SHAKE256,
  password: '0b'.repeat(22),
  salt: '000102030405060708090a0b0c',
  info: 'f0f1f2f3f4f5f6f7f8f9',
  keySize: '42',
}), 'd3288c49e445e58b10f1643a1628acba31a07734379b8ea1863660083ae6fc9b875e342abdfce97b7127');

assert.equal(run('KDF_PBKDF2', {
  digestType: ids.SHAKE128,
  password: '70617373776f7264',
  salt: '73616c74',
  iterations: '2',
  keySize: '32',
}), '216cd41b0be9ce4049517ec8942eeeee9ced8210030a062bcc1019508ad27586');

assert.equal(run('KDF_PBKDF2', {
  digestType: ids.SHAKE256,
  password: '70617373776f7264',
  salt: '73616c74',
  iterations: '2',
  keySize: '32',
}), '1759b2727a14aa7708c8b1845f05e4d1c731f19a9aaf747161ff0973b3c1bd27');

assert.equal(run('Digest', {
  digestType: ids.SHAKE256_114,
  haveParts: false,
  cleartext: '',
}).length, 228);

assert.equal(run('KDF_SCRYPT', {
  password: '70617373776f7264',
  salt: '4e61436c',
  N: '1024',
  r: '8',
  p: '4',
  keySize: '64',
}), '1ed1b3814e7bd065fea1b64fa617fb05ba290e301b2765b831876fb995044293cb8dc225ddc50b3dec862ae3c295d54caad62f4dfa00cf6853f8aa3ceb4354e0');

assert.equal(run('KDF_SCRYPT', {
  password: '70617373776f7264',
  salt: '4e61436c',
  N: '1024',
  r: '8',
  p: '5',
  keySize: '64',
}), undefined);

assert.equal(run('KDF_ARGON2', {
  password: '70617373776f7264',
  salt: '736f6d6573616c74',
  type: '2',
  threads: '4',
  memory: '32',
  iterations: '2',
  keySize: '32',
}), 'd74d7db154b312931625cde5a51f76bc52113b4b0515aa94952203b3cc45b800');

assert.equal(run('KDF_ARGON2', {
  password: '70617373776f7264',
  salt: '736f6d6573616c74',
  type: '2',
  threads: '5',
  memory: '32',
  iterations: '2',
  keySize: '32',
}), undefined);

assert.equal(run('KDF_ARGON2', {
  password: '70617373776f7264',
  salt: '736f6d6573616c74',
  type: '2',
  threads: '1',
  memory: '32',
  iterations: '2',
  keySize: '32',
}), '31111cc053ba0a799c0884148fd7ec9dc3631f3e8cf476cca9521d4ccc5136e8');

assert.equal(run('KDF_ARGON2', {
  password: '70617373776f7264',
  salt: '736f6d6573616c74',
  type: '2',
  threads: '1',
  memory: String(512 * 1024 + 4),
  iterations: '1',
  keySize: '4',
}), undefined);

console.log('noble-hashes adapter tests passed');
