import { hashesProject } from './hashes.mjs';
import { ciphersProject } from './ciphers.mjs';
import { curvesProject } from './curves.mjs';
import { postQuantumProject } from './post-quantum.mjs';

const projects = new Map([hashesProject, ciphersProject, curvesProject, postQuantumProject]
  .map((project) => [project.name, project]));

export function getProject(name) {
  const project = projects.get(name);
  if (project === undefined) throw new Error(`unsupported noblefuzz project ${JSON.stringify(name)}`);
  return project;
}

export function projectNames() {
  return [...projects.keys()];
}
