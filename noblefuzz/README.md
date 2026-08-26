# noblefuzz

Standalone high-throughput fuzzer for `@noble/hashes`, `@noble/ciphers`,
`@noble/curves`, and `@noble/post-quantum`, used by the reusable GitHub
workflow. Mutation, scheduling, semantic feedback, target calls, and result
checking run in one persistent Node/V8 process; Cryptofuzz is not involved.

Every case is deterministic and replayable. Coverage is semantic (algorithms,
operation combinations, length buckets, block boundaries, parameter sets)
plus source-level: one worker runs an Acorn-instrumented build and feeds
function/branch hits into the shared corpus, while throughput workers can
sample V8 precise coverage. The scheduler favors corpus entries that own rare
features. Raw-input cases mutate encoded keys, points, signatures, and
ciphertexts; rejection is a normal, coverage-feeding outcome.

## Profiles

| Project | Phase shares | Checked against |
| --- | --- | --- |
| `noble-hashes` | digest 65%, KDFs 30%, Argon2 5% | Node/OpenSSL, independent constructions |
| `noble-ciphers` | ciphers 100% | Node/OpenSSL, libsodium WASM, StableLib AES-SIV, known-answer tests |
| `noble-curves` | fast 95%, pairing 5% | Node/OpenSSL, tiny-secp256k1, mcl-wasm, ffjavascript/wasmcurves |
| `noble-post-quantum` | general 80%, SLH-DSA 20% | Node standards implementations, official liboqs WASM |

Where no fast independent implementation exists (AES-GCM-SIV, Salsa20-128,
bespoke hybrid KEM combiners), published known-answer tests and per-case
algebraic/lifecycle invariants are used instead. All oracles are exact
lockfile pins; the contract test rejects any oracle that depends on Noble,
and the pure-JS libsodium fallback is rejected at startup.

## Usage

```sh
npm --prefix noblefuzz ci
node noblefuzz/cli.mjs fuzz \
  --project noble-ciphers --phase ciphers --seconds 60 \
  --seed 1 --workers auto --max-len 4096 --timeout 600 \
  --guidance-workers 1 --coverage-seconds 30 \
  --corpus fuzz-corpus --artifacts fuzz-artifacts
```

Replay a failure or corpus, shrink a failure, or reduce a corpus (same
project/phase/max-len as the original run):

```sh
node noblefuzz/cli.mjs replay        --project noble-ciphers --phase ciphers --max-len 4096 fuzz-artifacts/failure-ciphers-....json
node noblefuzz/cli.mjs minimize      --project noble-ciphers --phase ciphers --max-len 4096 --output failure.min.json failure.json
node noblefuzz/cli.mjs reduce-corpus --project noble-ciphers --phase ciphers --max-len 4096 --output fuzz-corpus-min fuzz-corpus
```

Key options:

- `--workers`: explicit count, `auto`, CPU offset (`-1`), or share (`50%`).
  Relative forms cap at 10 workers; explicit counts up to 256. CLI default: 1.
- `--seed` / `FUZZ_SEED`: decimal or `0x`-hex up to 256 bits; SHA-256 domain
  separation derives a distinct ChaCha20 stream per project, phase, and worker.
- `--guidance-workers` / `NOBLEFUZZ_GUIDANCE_WORKERS`: instrumented guidance
  workers (workflow default 1, CLI default 0).
- `--coverage-seconds` / `NOBLEFUZZ_COVERAGE_SECONDS`: sampled V8 coverage
  interval for throughput workers (workflow default 30, CLI default off).
- `--source-dir` / `NOBLE_SOURCE_DIR`: fuzz a built Noble checkout instead of
  the pinned dependency.

The workflow runner picks its phase split from `NOBLE_MODULE`:

```sh
FUZZ_TOTAL_TIME=300 FUZZ_MAX_LEN=4096 FUZZ_SEED=1 NOBLEFUZZ_WORKERS=auto \
NOBLE_MODULE=noble-curves NOBLE_REPOSITORY=paulmillr/noble-curves \
NOBLE_SOURCE_PACKAGE=@noble/curves NOBLE_SOURCE_SHA=local \
NOBLE_SOURCE_DIR=/path/to/built/noble-curves \
./noblefuzz/run.sh
```

## Artifacts and supervision

Corpora are portable versioned JSON cases shared between workers through
atomic content-addressed publication. A mismatch or unexpected exception
writes the exact reproducer and report to `fuzz-artifacts` before failing.
Each phase writes merged `stats-<phase>.json` plus per-worker statistics
(operation counts, throughput, features, corpus size, worker seeds).

The parent CLI supervises the fleet and kills it if a worker crashes or stops
reporting for `--timeout` seconds (default 600, longer than the slowest
SLH-DSA operations). Artifacts are uploaded even after a failed workflow run.

The controlled-defect suite in [`mutation/`](mutation/README.md)
mutation-tests all four libraries with at least 15 defect classes each.
