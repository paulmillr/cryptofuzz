export class PRNG {
  constructor(seed) {
    this.state = Number(seed) >>> 0;
    if (this.state === 0) this.state = 0x9e3779b9;
  }

  next() {
    let value = this.state;
    value ^= value << 13;
    value ^= value >>> 17;
    value ^= value << 5;
    this.state = value >>> 0;
    return this.state;
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
    let word = 0;
    for (let index = 0; index < length; index++) {
      if ((index & 3) === 0) word = this.next();
      result[index] = word & 0xff;
      word >>>= 8;
    }
    return result;
  }
}
