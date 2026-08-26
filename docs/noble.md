# noble cryptography

Cryptofuzz has maintained adapters with reproducible default package pins:

| Package | Default pin | Coverage |
| --- | --- | --- |
| `@noble/ciphers` | 2.3.0 | AES modes, AES-KW/KWP, AES-GCM-SIV/SIV, ChaCha20, XChaCha20, and Salsa20 |
| `@noble/curves` | 2.3.0 | NIST and Brainpool curves, secp256k1, Ed25519/Ed448, X25519/X448, BLS12-381, and BN254 |
| `@noble/hashes` | 2.3.0 | Digests, HMAC, HKDF, PBKDF2, scrypt, and Argon2 |
| `@noble/post-quantum` | 0.7.0 | ML-KEM and hybrid KEMs; ML-DSA, SLH-DSA, and Falcon signatures |
| `@noble/secp256k1` | 3.1.0 | Standalone secp256k1 implementation |
| `@noble/ed25519` | 3.1.0 | Standalone Ed25519 implementation |

The project pins Node.js 24.19.0 in `.node-version`. The adapters support
Node.js 22 or newer; `noblefuzz` requires Node.js 24.7 or newer for its native
Argon2 oracle. The native fuzzer build also needs Bash, Clang with libFuzzer,
CMake, Make, Python 3, Git, npm, `curl`, and `tar`. The complete differential
build uses the pinned Go toolchain for its CIRCL post-quantum oracle.

To install the JavaScript dependencies, rebuild every adapter, and run their
operation-level test vectors:

```sh
make test-noble
```

To build a complete differential fuzzer with LibreSSL, Crypto++, mpdecimal,
blst, CIRCL, and all six Noble adapters:

```sh
./build.sh
```

For a quicker Noble-only fuzzer build:

```sh
./build.sh noble
```

After the first complete build, `./build.sh fast` reuses the already-built
native dependencies. The script honors `CC`, `CXX`, `CFLAGS`, and `CXXFLAGS`;
it defaults to `clang`, `clang++`, and sanitizer/libFuzzer instrumentation.

Post-quantum inputs carry explicit key-generation seeds, encapsulation coins,
signature contexts, and signing entropy. This makes standardized algorithms
deterministic across Noble and CIRCL while retaining randomized test cases.

The versions are pinned in each adapter's `package.json` and
`package-lock.json`, and builds use `npm ci`, so a build cannot silently change
its cryptographic implementation. To test a newer release, update the relevant
pin and lockfile and run `make test-noble` before rebuilding the native fuzzer.

## Testing a Git checkout

Each of the six adapters can instead bundle a built checkout of its primary
Noble package. This is intended for commit and pull-request fuzzing without
changing Cryptofuzz's reproducible default dependency pins. Build the checkout
first, then pass its absolute package-root path as `NOBLE_SOURCE_DIR`:

```sh
npm --prefix /path/to/noble-curves ci
npm --prefix /path/to/noble-curves run build
NOBLE_SOURCE_DIR=/path/to/noble-curves NOBLE_MODULE=noble-curves ./build.sh noble
```

Replace `noble-curves` in both paths with `noble-ciphers`, `noble-ed25519`,
`noble-hashes`, `noble-post-quantum`, or `noble-secp256k1` for the corresponding
project. The adapter validates that the checkout's `package.json` names the
expected primary package and fails if a required built entry point is absent.
Imports made by the checked-out package resolve through that checkout's
`npm ci` installation; harness-only dependencies still resolve through the
adapter's lockfile. When `NOBLE_SOURCE_DIR` is unset, the normal locked npm
package is used throughout.

## GitHub Actions

All six supported Noble repositories can fuzz their latest default-branch
commit every day with the reusable workflow in this repository. Add this
caller workflow to `noble-ciphers`, `noble-curves`, `noble-ed25519`,
`noble-hashes`, `noble-post-quantum`, or `noble-secp256k1`:

```yaml
name: Cryptofuzz

on:
  schedule:
    - cron: '0 14 * * *'

permissions:
  contents: read

jobs:
  fuzz:
    uses: paulmillr/cryptofuzz/.github/workflows/noble-commit-fuzz.yml@master
```

The reusable workflow derives the fuzzer from the caller repository's exact
name. It selects the standalone engine for `noble-hashes`, `noble-ciphers`,
`noble-curves`, and `noble-post-quantum`; the standalone `noble-ed25519` and
`noble-secp256k1` repositories retain their Cryptofuzz adapters. It validates
the selected source package before running. The workflow checks out and builds the latest commit on the
caller's default branch and fuzzes it for two hours at 14:00 UTC. Each run
records a fresh random seed and uploads its corpus and any crash artifact so a
finding can be reproduced. The primary package is bundled from that checkout,
not from the adapter's default npm pin. The post-quantum profile permits 64 KiB
corpus entries so its largest valid signature operations remain reachable; the
other profiles retain a 4 KiB cap.

The `noble-hashes` profile uses separate corpora and assigns 65% of its runtime
to digests, 30% to HMAC and non-Argon2 KDFs, and 5% to Argon2. Scrypt and
Argon2 parallelism is restricted to values from 1 through 4.

The curves profile assigns 95% to conventional curve, signature, point, field,
and BLS operations and 5% to pairings. The post-quantum profile assigns 80% to
KEMs, hybrid KEMs, ML-DSA, and Falcon and 20% to SLH-DSA. Ciphers use one
phase covering all supported modes.

These four repositories run through the standalone
[`noblefuzz`](../noblefuzz/README.md) engine. Mutation, scheduling, semantic
coverage, Noble calls, and differential checks remain in persistent V8 worker
processes; the workflow uses all available CPUs (capped at 10) and does not
build or launch Cryptofuzz for these packages. Set `NOBLEFUZZ_WORKERS=1` for a
serial run.
Raw encoded keys, points, signatures, ciphertexts, and malformed cipher shapes
are fuzzed separately from valid lifecycles. Workers continuously import each
other's corpus entries for field crossover. By default, one worker uses
source-level function and branch instrumentation continuously while the other
workers remain uninstrumented; rare-feature corpus entries receive additional
mutation energy. Set `NOBLEFUZZ_GUIDANCE_WORKERS=0` to disable that worker. The
throughput workers also take a low-duty-cycle V8 precise-coverage sample (one
testcase every 30 seconds by default); set `NOBLEFUZZ_COVERAGE_SECONDS=0` to
disable it. The parent deduplicates feature discoveries across workers. The CLI
also provides non-destructive corpus reduction and deterministic failure
minimization.
Independent oracles include Node/OpenSSL, StableLib, tiny-secp256k1 WASM,
mcl WASM, ffjavascript/wasmcurves, and official liboqs WASM. Published
known-answer tests and algebraic invariants cover the few algorithms without a
suitable fast independent npm implementation. Corpora, exact failure
reproducers, per-operation timing, and run metadata retain the existing
workflow artifact paths.

The four corresponding Cryptofuzz adapters remain available for local
compatibility and reference comparisons. The hashes adapter's opt-in persistent
Node worker maps V8 coverage back to libFuzzer counters; without that opt-in it
uses the embedded QuickJS path.

Pin `@master` to a full Cryptofuzz commit SHA if an immutable workflow revision
is preferred. Do not inherit secrets: the selected Noble commit's npm build
scripts execute in the job.
