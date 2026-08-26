import fs from 'node:fs';
import inspector from 'node:inspector';
import './noble-hashes.js';

const session = new inspector.Session();
session.connect();

function post(method, parameters = {}) {
  return new Promise((resolve, reject) => {
    session.post(method, parameters, (error, result) => error ? reject(error) : resolve(result));
  });
}

function readExact(size, allowEof = false) {
  const result = Buffer.allocUnsafe(size);
  let offset = 0;
  while (offset !== size) {
    const count = fs.readSync(0, result, offset, size - offset, null);
    if (count === 0) {
      if (allowEof && offset === 0) return;
      throw new Error('truncated request');
    }
    offset += count;
  }
  return result;
}

function writeExact(buffer) {
  let offset = 0;
  while (offset !== buffer.length) offset += fs.writeSync(1, buffer, offset, buffer.length - offset);
}

function coverageIndex(startOffset, endOffset) {
  let value = Math.imul(startOffset ^ 0x9e3779b9, 0x85ebca6b);
  value ^= Math.imul(endOffset ^ (value >>> 16), 0xc2b2ae35);
  return (value ^ (value >>> 16)) & 0xffff;
}

const counters = new Uint8Array(65536);
const touched = [];

function encodeResponse(output, preciseCoverage) {
  touched.length = 0;

  for (const script of preciseCoverage.result) {
    if (!script.url.endsWith('/noble-hashes.js')) continue;
    for (const func of script.functions) {
      for (const range of func.ranges) {
        if (range.count === 0) continue;
        const index = coverageIndex(range.startOffset, range.endOffset);
        if (counters[index] === 0) touched.push(index);
        counters[index] = Math.min(128, counters[index] + Math.min(128, range.count));
      }
    }
  }

  const outputBytes = output === undefined
    ? new Uint8Array()
    : typeof output === 'string' ? Buffer.from(output) : output;
  const response = Buffer.allocUnsafe(1 + 4 + outputBytes.length + 2 + touched.length * 3);
  let offset = 0;
  response[offset++] = output === undefined ? 0 : 1;
  response.writeUInt32LE(outputBytes.length, offset);
  offset += 4;
  response.set(outputBytes, offset);
  offset += outputBytes.length;
  response.writeUInt16LE(touched.length, offset);
  offset += 2;
  for (const index of touched) {
    response.writeUInt16LE(index, offset);
    offset += 2;
    response[offset++] = counters[index];
    counters[index] = 0;
  }

  const header = Buffer.allocUnsafe(4);
  header.writeUInt32LE(response.length);
  writeExact(header);
  writeExact(response);
}

function runRequest(request) {
  if (request.length < 1) throw new Error('request is too short');
  const operation = request[0];
  if (operation === 1) return globalThis.CryptofuzzRun(request.subarray(1).toString());
  if (operation !== 0 || request.length < 14) throw new Error('unknown request operation');

  let offset = 1;
  const digestType = request.readBigUInt64LE(offset).toString();
  offset += 8;
  const multipart = request[offset++] === 0 ? '0' : '1';
  const partCount = request.readUInt32LE(offset);
  offset += 4;
  const parts = [];
  for (let i = 0; i < partCount; i++) {
    if (offset + 4 > request.length) throw new Error('truncated part length');
    const length = request.readUInt32LE(offset);
    offset += 4;
    if (offset + length > request.length) throw new Error('truncated part');
    parts.push(request.subarray(offset, offset + length));
    offset += length;
  }
  if (offset !== request.length) throw new Error('trailing request bytes');
  return globalThis.CryptofuzzDigest(digestType, multipart, parts);
}

await post('Profiler.enable');
await post('Profiler.startPreciseCoverage', {
  callCount: false,
  detailed: true,
  allowTriggeredUpdates: false,
});

try {
  for (;;) {
    const header = readExact(4, true);
    if (header === undefined) break;
    const requestSize = header.readUInt32LE();
    if (requestSize === 0) break;
    if (requestSize > 16 * 1024 * 1024) throw new Error('request is too large');
    const output = runRequest(readExact(requestSize));
    encodeResponse(output, await post('Profiler.takePreciseCoverage'));
  }
} finally {
  await post('Profiler.stopPreciseCoverage');
  session.disconnect();
}
