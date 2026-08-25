import { build } from 'esbuild';
import { nobleSourcePlugin } from '../noble-source.mjs';

const sourcePlugin = await nobleSourcePlugin('@noble/post-quantum');

await build({
  entryPoints: ['harness.js'],
  outfile: 'noble-post-quantum.js',
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2020',
  plugins: sourcePlugin === undefined ? [] : [sourcePlugin],
  banner: {
    js: `if (!Object.hasOwn) {
  Object.hasOwn = function (object, property) {
    return Object.prototype.hasOwnProperty.call(object, property);
  };
}`,
  },
});
