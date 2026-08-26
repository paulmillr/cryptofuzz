import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function selectExport(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    for (const candidate of value) {
      const selected = selectExport(candidate);
      if (selected !== undefined) return selected;
    }
  } else if (value !== null && typeof value === 'object') {
    for (const condition of ['node', 'import', 'module', 'default', 'browser']) {
      if (Object.hasOwn(value, condition)) {
        const selected = selectExport(value[condition]);
        if (selected !== undefined) return selected;
      }
    }
  }
  return undefined;
}

function resolveExport(exportsField, subpath) {
  const exact = selectExport(exportsField?.[subpath]);
  if (exact !== undefined) return exact;
  if (exportsField === null || typeof exportsField !== 'object') return undefined;
  for (const [pattern, value] of Object.entries(exportsField)) {
    const star = pattern.indexOf('*');
    if (star === -1) continue;
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    if (!subpath.startsWith(prefix) || !subpath.endsWith(suffix)) continue;
    const replacement = subpath.slice(prefix.length, subpath.length - suffix.length);
    const selected = selectExport(value);
    if (selected !== undefined) return selected.replaceAll('*', replacement);
  }
  return undefined;
}

export async function packageImporter(packageName, sourceDirectory) {
  if (!sourceDirectory) return (subpath) => import(`${packageName}/${subpath}`);

  const root = await realpath(path.resolve(sourceDirectory));
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  if (manifest.name !== packageName) {
    throw new Error(`source directory contains ${JSON.stringify(manifest.name)}, expected ${JSON.stringify(packageName)}`);
  }

  return async (subpath) => {
    const exportName = `./${subpath}`;
    let relative = resolveExport(manifest.exports, exportName);
    if (relative === undefined) relative = exportName;
    if (typeof relative !== 'string' || !relative.startsWith('./')) {
      throw new Error(`cannot resolve ${exportName} from ${root}`);
    }
    const filename = path.resolve(root, relative);
    const withinRoot = path.relative(root, filename);
    if (withinRoot === '..' || withinRoot.startsWith(`..${path.sep}`) || path.isAbsolute(withinRoot)) {
      throw new Error(`package export ${relative} escapes ${root}`);
    }
    return import(pathToFileURL(filename).href);
  };
}
