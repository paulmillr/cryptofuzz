import { existsSync } from 'node:fs';
import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

const sourceEnvironmentVariable = 'NOBLE_SOURCE_DIR';

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function selectConditionalExport(value) {
  if (typeof value === 'string') return value;

  if (Array.isArray(value)) {
    for (const candidate of value) {
      const selected = selectConditionalExport(candidate);
      if (selected !== undefined) return selected;
    }
    return undefined;
  }

  if (value !== null && typeof value === 'object') {
    // Match esbuild's browser ESM build closely. The final loop also keeps the
    // helper useful if Noble introduces a new condition in a future commit.
    for (const condition of ['browser', 'import', 'module', 'default', 'node']) {
      if (Object.hasOwn(value, condition)) {
        const selected = selectConditionalExport(value[condition]);
        if (selected !== undefined) return selected;
      }
    }
    for (const candidate of Object.values(value)) {
      const selected = selectConditionalExport(candidate);
      if (selected !== undefined) return selected;
    }
  }

  return undefined;
}

function replaceAsterisk(value, replacement) {
  if (typeof value === 'string') return value.replaceAll('*', replacement);
  if (Array.isArray(value)) {
    return value.map((candidate) => replaceAsterisk(candidate, replacement));
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, candidate]) => [key, replaceAsterisk(candidate, replacement)]),
    );
  }
  return value;
}

function findExport(exportsField, subpath) {
  if (typeof exportsField === 'string' || Array.isArray(exportsField)) {
    return subpath === '.' ? selectConditionalExport(exportsField) : undefined;
  }

  if (exportsField === null || typeof exportsField !== 'object') return undefined;

  if (Object.hasOwn(exportsField, subpath)) {
    return selectConditionalExport(exportsField[subpath]);
  }

  if (subpath === '.' && !Object.keys(exportsField).some((key) => key.startsWith('.'))) {
    return selectConditionalExport(exportsField);
  }

  for (const [pattern, value] of Object.entries(exportsField)) {
    const asterisk = pattern.indexOf('*');
    if (asterisk === -1) continue;

    const prefix = pattern.slice(0, asterisk);
    const suffix = pattern.slice(asterisk + 1);
    if (!subpath.startsWith(prefix) || !subpath.endsWith(suffix)) continue;

    const replacement = subpath.slice(prefix.length, subpath.length - suffix.length);
    return selectConditionalExport(replaceAsterisk(value, replacement));
  }

  return undefined;
}

function packageSubpath(specifier, packageName) {
  if (specifier === packageName) return '.';
  return `.${specifier.slice(packageName.length)}`;
}

export async function nobleSourcePlugin(expectedPackageName) {
  const configuredSource = process.env[sourceEnvironmentVariable];
  if (configuredSource === undefined || configuredSource.length === 0) return undefined;

  let sourceDirectory;
  try {
    sourceDirectory = await realpath(path.resolve(configuredSource));
  } catch (error) {
    throw new Error(`${sourceEnvironmentVariable} must name an existing package directory`, {
      cause: error,
    });
  }

  const manifestPath = path.join(sourceDirectory, 'package.json');
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  } catch (error) {
    throw new Error(`${sourceEnvironmentVariable} must contain a readable package.json: ${manifestPath}`, {
      cause: error,
    });
  }

  if (manifest.name !== expectedPackageName) {
    throw new Error(
      `${sourceEnvironmentVariable} contains ${JSON.stringify(manifest.name)}, expected ${JSON.stringify(expectedPackageName)}`,
    );
  }

  const importFilter = new RegExp(`^${escapeRegularExpression(expectedPackageName)}(?:/.*)?$`);
  console.error(`[cryptofuzz] Bundling ${expectedPackageName} from ${sourceDirectory}`);

  return {
    name: 'cryptofuzz-noble-source',
    setup(build) {
      build.onResolve({ filter: importFilter }, (args) => {
        const subpath = packageSubpath(args.path, expectedPackageName);
        let target = findExport(manifest.exports, subpath);

        // Older Noble commits did not always enumerate every ESM entry point.
        if (target === undefined && subpath !== '.') target = subpath;
        if (target === undefined) {
          target = manifest.module ?? manifest.main;
          if (typeof target === 'string' && !target.startsWith('./')) target = `./${target}`;
        }

        if (typeof target !== 'string' || !target.startsWith('./')) {
          throw new Error(`Cannot resolve ${args.path} from ${manifestPath}`);
        }

        const resolvedTarget = path.resolve(sourceDirectory, target);
        const relativeTarget = path.relative(sourceDirectory, resolvedTarget);
        if (
          relativeTarget === '..' ||
          relativeTarget.startsWith(`..${path.sep}`) ||
          path.isAbsolute(relativeTarget)
        ) {
          throw new Error(`Package export ${JSON.stringify(target)} escapes ${sourceDirectory}`);
        }
        if (!existsSync(resolvedTarget)) {
          throw new Error(
            `${args.path} resolves to missing file ${resolvedTarget}; build the Noble checkout before building Cryptofuzz`,
          );
        }

        return { path: resolvedTarget };
      });
    },
  };
}
