import { createCipheriv, createHash } from 'node:crypto';
import { seedBytes } from './seed.mjs';

const BUFFER_BYTES = 16 * 1024;
const ZEROES = Buffer.alloc(BUFFER_BYTES);

export class PRNG {
  constructor(seed) {
    const key = createHash('sha256')
      .update('noblefuzz-prng-v2\0')
      .update(seedBytes(seed))
      .digest();
    this.cipher = createCipheriv('chacha20', key, Buffer.alloc(16));
    this.buffer = Buffer.alloc(0);
    this.offset = 0;
  }

  refill() {
    this.buffer = this.cipher.update(ZEROES);
    this.offset = 0;
  }

  next() {
    if (this.buffer.length - this.offset >= 4) {
      const value = this.buffer.readUInt32LE(this.offset);
      this.offset += 4;
      return value;
    }
    let value = 0;
    for (let shift = 0; shift < 32; shift += 8) {
      if (this.offset === this.buffer.length) this.refill();
      value |= this.buffer[this.offset++] << shift;
    }
    return value >>> 0;
  }

  int(limit) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('limit must be positive');
    return Math.floor((this.next() / 0x100000000) * limit);
  }

  bool(numerator = 1, denominator = 2) {
    return this.int(denominator) < numerator;
  }

  pick(values) {
    if (values.length === 0) throw new RangeError('cannot pick from an empty array');
    return values[this.int(values.length)];
  }

  bytes(length) {
    const result = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      if (this.offset === this.buffer.length) this.refill();
      const count = Math.min(length - written, this.buffer.length - this.offset);
      result.set(this.buffer.subarray(this.offset, this.offset + count), written);
      this.offset += count;
      written += count;
    }
    return result;
  }
}
