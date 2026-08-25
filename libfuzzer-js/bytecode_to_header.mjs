import fs from 'node:fs';
import path from 'node:path';

const input = process.argv[2];
if (!input) {
  console.error('Usage: node bytecode_to_header.mjs <bytecode>');
  process.exit(1);
}

const bytes = fs.readFileSync(input);
const symbol = path.basename(input).replace(/[^A-Za-z0-9_]/g, '_');
const lines = [];
for (let offset = 0; offset < bytes.length; offset += 12) {
  const values = [...bytes.subarray(offset, offset + 12)].map((byte) => `0x${byte.toString(16).padStart(2, '0')}`);
  lines.push(`  ${values.join(', ')}${offset + 12 < bytes.length ? ',' : ''}`);
}

process.stdout.write(
  `unsigned char ${symbol}[] = {\n${lines.join('\n')}\n};\n` +
  `unsigned int ${symbol}_len = ${bytes.length};\n`
);
