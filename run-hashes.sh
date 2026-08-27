#!/usr/bin/env bash
  set -euo pipefail

  npm --prefix noblefuzz ci

  FUZZ_TOTAL_TIME="${FUZZ_TOTAL_TIME:-300}"
  FUZZ_MAX_LEN=4096
  FUZZ_SEED="${FUZZ_SEED:-1}"
  NOBLEFUZZ_WORKERS="${NOBLEFUZZ_WORKERS:-auto}"

  run_phase() {
    local phase="$1"
    local seconds="$2"

    node noblefuzz/cli.mjs fuzz \
      --project noble-hashes \
      --phase "$phase" \
      --seconds "$seconds" \
      --seed "$FUZZ_SEED" \
      --workers "$NOBLEFUZZ_WORKERS" \
      --guidance-workers 1 \
      --coverage-seconds 30 \
      --max-len "$FUZZ_MAX_LEN" \
      --timeout 600 \
      --corpus "fuzz-output/noble-hashes/corpus-$phase" \
      --artifacts "fuzz-output/noble-hashes/artifacts"
  }

  run_phase digest "$((FUZZ_TOTAL_TIME * 65 / 100))"
  run_phase kdfs   "$((FUZZ_TOTAL_TIME * 30 / 100))"
  run_phase argon2 "$((FUZZ_TOTAL_TIME - FUZZ_TOTAL_TIME * 95 / 100))"
