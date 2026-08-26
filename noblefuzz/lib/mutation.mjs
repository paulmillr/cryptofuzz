export function cloneCase(testcase) {
  return Object.fromEntries(Object.entries(testcase).map(([key, value]) => {
    if (value instanceof Uint8Array) return [key, Uint8Array.from(value)];
    if (Array.isArray(value)) return [key, value.slice()];
    return [key, value];
  }));
}

export function byteSize(testcase) {
  return Object.values(testcase).reduce((size, value) => size + (value instanceof Uint8Array ? value.length : 0), 0);
}

function patternedBytes(prng, length) {
  const mode = prng.int(6);
  if (mode === 0) return new Uint8Array(length);
  if (mode === 1) return new Uint8Array(length).fill(0xff);
  if (mode === 2) return new Uint8Array(length).fill(prng.next() & 0xff);
  if (mode === 3) return Uint8Array.from({ length }, (_, index) => index & 0xff);
  return prng.bytes(length);
}

// Raw crypto objects need length mutations as well as bit flips: most parser
// and rejection bugs sit just to either side of a valid encoding boundary.
export function mutateBytes(bytes, prng, maximumLength, donor) {
  let result = Uint8Array.from(bytes);
  const limit = Math.max(0, maximumLength);
  const action = prng.int(donor === undefined ? 9 : 10);
  if (action <= 2 && result.length > 0) {
    const index = prng.int(result.length);
    result[index] ^= 1 << prng.int(8);
  } else if (action === 3 && result.length > 0) {
    result[prng.int(result.length)] = prng.next() & 0xff;
  } else if (action === 4 && result.length > 0) {
    const index = prng.int(result.length);
    result = Uint8Array.from([...result.subarray(0, index), ...result.subarray(index + 1)]);
  } else if (action === 5 && result.length < limit) {
    const index = prng.int(result.length + 1);
    result = Uint8Array.from([...result.subarray(0, index), prng.next() & 0xff, ...result.subarray(index)]);
  } else if (action === 6 && result.length > 1) {
    const start = prng.int(result.length);
    const count = 1 + prng.int(result.length - start);
    result = Uint8Array.from([...result.subarray(0, start), ...result.subarray(start + count)]);
  } else if (action === 7 && result.length > 0 && result.length < limit) {
    const start = prng.int(result.length);
    const count = Math.min(result.length - start, limit - result.length);
    result = Uint8Array.from([...result, ...result.subarray(start, start + count)]);
  } else if (action === 9 && donor !== undefined) {
    result = Uint8Array.from(donor.subarray(0, limit));
  } else {
    const boundaries = [0, 1, 2, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256]
      .filter((length) => length <= limit);
    const length = boundaries.length > 0 && prng.bool(4, 5) ? prng.pick(boundaries) : prng.int(limit + 1);
    result = patternedBytes(prng, length);
  }
  return result.length <= limit ? result : result.subarray(0, limit);
}

export function compatibleDonor(corpus, testcase, fields, prng, discriminator) {
  if (corpus === undefined) return;
  const candidates = (corpus.byOperation.get(testcase.operation) ?? []).filter((candidate) =>
    candidate !== testcase && discriminator(candidate, testcase) && fields.some((field) => candidate[field] instanceof Uint8Array));
  return candidates.length === 0 ? undefined : prng.pick(candidates);
}
