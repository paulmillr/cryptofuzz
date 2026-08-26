# noblefuzz

`noblefuzz` is the high-throughput standalone fuzzer used by the reusable
GitHub workflow for `@noble/hashes`, `@noble/ciphers`, `@noble/curves`, and
`@noble/post-quantum`. Mutation, scheduling, semantic feedback, target calls,
and result checking stay in one persistent Node/V8 process; these profiles do
not build or launch Cryptofuzz.

## Profiles and checks

| Project | Phase shares | Coverage and independent oracles |
| --- | --- | --- |
| `noble-hashes` | digest 65%, KDFs 30%, Argon2 5% | 30 digests, streaming, HMAC, HKDF, PBKDF2, scrypt, and all Argon2 modes; Node/OpenSSL and independent constructions |
| `noble-ciphers` | ciphers 100% | all 34 adapter variants; Node/OpenSSL, StableLib, and standards known-answer tests |
| `noble-curves` | fast 95%, pairing 5% | all 41 non-pairing adapter operations plus pairing/final exponentiation; Node/OpenSSL, tiny-secp256k1 WASM, mcl WASM, and ffjavascript/wasmcurves |
| `noble-post-quantum` | general 80%, SLH-DSA 20% | all KEM, hybrid KEM, ML-DSA, SLH-DSA, and Falcon identifiers; native Node standards implementations and official liboqs WASM |

Every generated case is deterministic and replayable. Semantic coverage tracks
algorithms, operation/algorithm combinations, important input-length buckets,
block boundaries, contexts, parameter sets, and exceptional patterns. One
workflow worker continuously runs an Acorn-instrumented build of the target and
feeds function and branch hits back into the shared corpus. The other workers
run uninstrumented for throughput and can additionally sample one testcase
every 30 seconds with V8 precise block coverage. Only new Noble-package ranges
enter the corpus. Scrypt `p` and Argon2 parallelism are restricted to the
inclusive range 1 through 4.

Corpus entries own the exact internal and semantic features they discovered.
The scheduler favors entries with rare features, grants them up to four
mutations, and occasionally chains mutations. Workers atomically claim new
features through the parent, so the fleet does not retain one redundant case
per worker for the same discovery.

Curves, ciphers, KEMs, and post-quantum signatures have separate raw-input
cases. They mutate encoded public and secret keys, points, signatures,
ciphertexts, IVs, and parameters with truncation, extension, duplication,
boundary lengths, and cross-case field replacement. Rejection is a normal
outcome and is itself coverage feedback. The complete raw values are stored in
the JSON reproducer rather than regenerated during replay.

Cipher cases separately fuzz encryption and arbitrary valid-shape decryption,
including matched acceptance/rejection and authenticated-tampering paths.
AES-GCM-SIV and Salsa20-128 do not have a suitable fast independent npm/WASM
implementation. They use published known-answer tests plus per-case
encrypt/decrypt invariants. Bespoke hybrid KEM combiners use lifecycle and
corruption invariants where no interoperable implementation exists. BN254 uses
algebraic invariants plus ffjavascript's independent WASM group and pairing
backend. Other paths apply every compatible independent implementation
alongside algebraic, codec, lifecycle, and corruption invariants.

## Oracle selection

The choices were checked against the upstream
[`noble-ciphers` third-party benchmark](https://github.com/paulmillr/noble-ciphers/blob/main/benchmark/thirdparty/index.ts)
and [`noble-curves` candidate manifest](https://github.com/paulmillr/noble-curves/blob/main/benchmark/thirdparty/package.json):

| Native gap | Selected package | Reason |
| --- | --- | --- |
| Salsa20, XChaCha20-Poly1305, AES-SIV | StableLib 2.x | Fast implementation used by the upstream cipher benchmark; current libsodium npm wrappers advertise pure JavaScript rather than WASM |
| secp256k1 Schnorr/point checks | `tiny-secp256k1` 2.2.4 | Independent BitcoinJS WASM implementation |
| BLS12-381 | `mcl-wasm` 2.2.0 | Small, fast pairing-oriented WASM implementation |
| BN254/alt-bn128 | `ffjavascript` 0.3.1 / `wasmcurves` | Established iden3 WASM field, group, and pairing backend |
| Falcon | `@oqs/liboqs-js` 0.15.1 | Official Open Quantum Safe SIMD-WASM build |

The upstream ChainSafe WASM candidate only duplicates ordinary
ChaCha20-Poly1305, already covered by Node/OpenSSL. The available
AES-GCM-SIV/XChaCha npm WASM search results were new or niche and were not
selected without upstream benchmark evidence. All oracle versions are exact
lockfile pins, and the contract test rejects an oracle that directly depends on
Noble.

## Run it

Install and run a phase against the pinned packages:

```sh
npm --prefix noblefuzz ci
node noblefuzz/cli.mjs fuzz \
  --project noble-ciphers --phase ciphers --seconds 60 \
  --seed 1 --workers auto --max-len 4096 --timeout 600 \
  --guidance-workers 1 \
  --coverage-seconds 30 \
  --corpus fuzz-corpus --artifacts fuzz-artifacts
```

`--workers` accepts an explicit count, `auto`, a CPU offset such as `-1`, or a
share such as `50%`/`0.5`. Relative forms use Node's cgroup- and
affinity-aware available parallelism and cap themselves at 10 workers;
explicit counts up to 256 are honored. Direct CLI use defaults to one worker.
The workflow runner defaults `NOBLEFUZZ_WORKERS` to `auto`; set it to `1` for a
serial run. It dedicates one worker to continuous source-level guidance; set
`NOBLEFUZZ_GUIDANCE_WORKERS=0` to disable it or pass `--guidance-workers` to the
CLI. Direct CLI use defaults to zero guidance workers. The workflow also
defaults `NOBLEFUZZ_COVERAGE_SECONDS` to 30; set it to `0` to disable the
throughput workers' sampled V8 coverage. Direct CLI use leaves sampling
disabled unless `--coverage-seconds` or deterministic `--coverage-every` is
supplied.

Set `NOBLE_SOURCE_DIR` or pass `--source-dir` to fuzz a built Noble checkout
instead of the pinned dependency. Its `package.json` name must match the
selected project and its built JavaScript exports must exist.

The controlled-defect suite in [`mutation/`](mutation/README.md) mutation-tests
all four source checkouts with at least 15 distinct defect classes per library.
It runs each mutant in an isolated package copy and emits machine-readable JSON
plus a compact Markdown audit report.

Replay one failure or a corpus with the same project and phase:

```sh
node noblefuzz/cli.mjs replay \
  --project noble-ciphers --phase ciphers --max-len 4096 \
  fuzz-artifacts/failure-ciphers-....json
```

Shrink a failure while preserving the same error identity, or non-destructively
reduce a corpus while preserving its full feature union:

```sh
node noblefuzz/cli.mjs minimize \
  --project noble-ciphers --phase ciphers --max-len 4096 \
  --output failure.min.json failure.json

node noblefuzz/cli.mjs reduce-corpus \
  --project noble-ciphers --phase ciphers --max-len 4096 \
  --output fuzz-corpus-min fuzz-corpus
```

The workflow-compatible runner selects its phase split from `NOBLE_MODULE`:

```sh
FUZZ_TOTAL_TIME=300 FUZZ_MAX_LEN=4096 FUZZ_SEED=1 NOBLEFUZZ_WORKERS=auto \
NOBLE_MODULE=noble-curves NOBLE_REPOSITORY=paulmillr/noble-curves \
NOBLE_SOURCE_PACKAGE=@noble/curves NOBLE_SOURCE_SHA=local \
NOBLE_SOURCE_DIR=/path/to/built/noble-curves \
./noblefuzz/run.sh
```

## Artifacts and supervision

Corpora are portable versioned JSON cases. Workers use independent,
deterministically derived seeds and share the content-addressed corpus through
atomic publication. They reload sibling discoveries once per second and use
compatible raw entries as field-crossover pools; only worker zero performs
bootstrap replay and seed-case coverage. A caught mismatch or exception
writes the exact reproducer and a report to `fuzz-artifacts` before failing.
Every phase also writes operation counts, sampled costs, estimated time shares,
throughput, feature count, source-guidance counts, rarity-scheduled runs,
mutation steps, corpus size, worker roles, worker count, and worker seeds. The
parent writes merged `stats-<phase>.json`; individual worker statistics remain
as `stats-<phase>-worker-<id>.json`.

The parent CLI supervises the complete process fleet and kills it if any worker
crashes or stops reporting progress for `--timeout` seconds. The timeout
report, run metadata, phase corpora, and failure files are uploaded even after
a failed workflow run. The default 600-second watchdog is deliberately longer
than the slowest SLH-DSA operations. Argon2 and scrypt `p <= 4` applies inside
each testcase and is independent of the number of fuzzer workers.
