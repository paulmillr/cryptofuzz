# Cryptofuzz - Differential cryptography fuzzing

Cryptofuzz was originally created by
[Guido Vranken (`guidovranken`)](https://github.com/guidovranken).

It has found bugs in many cryptographic projects, including:

- OpenSSL
- LibreSSL
- BoringSSL
- NSS
- Botan
- Crypto++
- wolfSSL/wolfCrypt
- Mbed TLS
- libgcrypt
- Zig

This is fork of cryptofuzz, specifically for noble cryptography.

## Documentation

For building Cryptofuzz, please refer to [`docs/building.md`](docs/building.md).

For instructions on how to run Cryptofuzz, please see
[`docs/running.md`](docs/running.md).

The supported toolchains, pinned third-party revisions, and legacy adapter
boundaries are documented in [`docs/dependencies.md`](docs/dependencies.md).

## Scheduled and manual Noble fuzzing

Save the following as `.github/workflows/cryptofuzz.yml` in any of the six
supported Noble repositories:

```yaml
name: Fuzz

on:
  workflow_dispatch:
    inputs:
      ref:
        description: Noble git ref or commit to fuzz
        required: false
        type: string
  schedule:
    - cron: '0 14 * * *'

permissions:
  contents: read

jobs:
  fuzz:
    uses: paulmillr/cryptofuzz/.github/workflows/noble-commit-fuzz.yml@c13a8e7a38f02a31509b5e5a355e3ed395a401bd
    with:
      ref: ${{ inputs.ref || github.sha }}
```

This runs every day at 14:00 UTC against the latest commit on the Noble
repository's default branch. It can also be started from **Actions →
Cryptofuzz → Run workflow**, optionally with a branch, tag, or commit in
`ref`. The manual button appears after this caller workflow is present on the
repository's default branch.

The reusable workflow derives the adapter from the repository name, fuzzes
only that adapter for two hours with a fresh random seed, and uploads the
resulting corpus and crash artifacts. Its `uses` reference is pinned to a full
Cryptofuzz commit SHA; update that SHA explicitly when upgrading the workflow.

The supported repository names are `noble-ciphers`, `noble-curves`,
`noble-ed25519`, `noble-hashes`, `noble-post-quantum`, and
`noble-secp256k1`.
