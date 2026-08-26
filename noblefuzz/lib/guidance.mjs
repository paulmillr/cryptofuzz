import { readFile, realpath } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GuidanceTracker, instrumentSource } from './instrumenter.mjs';

async function packageRoot(packageName, sourceDirectory) {
  if (sourceDirectory !== undefined) return realpath(path.resolve(sourceDirectory));
  let directory = path.dirname(fileURLToPath(import.meta.resolve(packageName)));
  while (true) {
    try {
      const manifest = JSON.parse(await readFile(path.join(directory, 'package.json'), 'utf8'));
      if (manifest.name === packageName) return realpath(directory);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const parent = path.dirname(directory);
    if (parent === directory) throw new Error(`cannot locate package root for ${packageName}`);
    directory = parent;
  }
}

export async function enableGuidance(packageName, sourceDirectory) {
  const root = await packageRoot(packageName, sourceDirectory);
  const tracker = new GuidanceTracker();
  globalThis.__noblefuzzHit = tracker.hit;
  registerHooks({
    load(url, context, nextLoad) {
      const loaded = nextLoad(url, context);
      if (loaded.format !== 'module' || !url.startsWith('file:')) return loaded;
      const filename = fileURLToPath(url.split('?')[0]);
      const relative = path.relative(root, filename);
      if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        return loaded;
      }
      if (relative === 'node_modules' || relative.startsWith(`node_modules${path.sep}`)) return loaded;
      if (!/\.(?:js|mjs)$/.test(filename)) return loaded;
      const source = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8');
      return { ...loaded, source: instrumentSource(source, relative.split(path.sep).join('/')) };
    },
  });
  return { root, tracker };
}
