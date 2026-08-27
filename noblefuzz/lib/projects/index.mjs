import { hashesProject } from './hashes.mjs';
import { ciphersProject } from './ciphers.mjs';
import { curvesProject } from './curves.mjs';
import { ed25519Project } from './ed25519.mjs';
import { postQuantumProject } from './post-quantum.mjs';
import { secp256k1Project } from './secp256k1.mjs';

const projects = new Map([
  hashesProject,
  ciphersProject,
  curvesProject,
  postQuantumProject,
  secp256k1Project,
  ed25519Project,
]
  .map((project) => [project.name, project]));

export function getProject(name) {
  const project = projects.get(name);
  if (project === undefined) throw new Error(`unsupported noblefuzz project ${JSON.stringify(name)}`);
  return project;
}

export function projectNames() {
  return [...projects.keys()];
}
