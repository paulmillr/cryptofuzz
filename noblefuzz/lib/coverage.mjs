import { Session } from 'node:inspector/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function sourceMatcher(packageName, sourceDirectory) {
  if (sourceDirectory !== undefined) {
    const prefix = `${pathToFileURL(path.resolve(sourceDirectory)).href.replace(/\/$/, '')}/`;
    return (url) => url.startsWith(prefix) ? url.slice(prefix.length) : undefined;
  }
  const marker = `/node_modules/${packageName}/`;
  return (url) => {
    const index = url.indexOf(marker);
    return index === -1 ? undefined : url.slice(index + marker.length);
  };
}

export class CoverageSampler {
  constructor(packageName, sourceDirectory) {
    this.session = new Session();
    this.session.connect();
    this.relativeSource = sourceMatcher(packageName, sourceDirectory);
    this.ready = this.session.post('Profiler.enable');
  }

  async capture(call) {
    await this.ready;
    await this.session.post('Profiler.startPreciseCoverage', { callCount: false, detailed: true });
    let value;
    let failure;
    try {
      value = call();
    } catch (error) {
      failure = error;
    }
    let report;
    try {
      report = await this.session.post('Profiler.takePreciseCoverage');
    } finally {
      await this.session.post('Profiler.stopPreciseCoverage');
    }
    if (failure !== undefined) throw failure;
    return { value, features: this.#features(report.result) };
  }

  #features(scripts) {
    const features = [];
    for (const script of scripts) {
      const source = this.relativeSource(script.url);
      if (source === undefined) continue;
      for (const fn of script.functions) {
        for (const range of fn.ranges) {
          if (range.count !== 0) features.push(`v8:${source}:${range.startOffset}:${range.endOffset}`);
        }
      }
    }
    return [...new Set(features)];
  }

  async close() {
    await this.ready;
    await this.session.post('Profiler.disable');
    this.session.disconnect();
  }
}
