#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

required_variables=(FUZZ_MAX_LEN FUZZ_SEED NOBLE_MODULE NOBLE_REPOSITORY NOBLE_SOURCE_PACKAGE NOBLE_SOURCE_SHA NOBLE_SOURCE_DIR)
for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
        echo "Missing required environment variable: $variable" >&2
        exit 1
    fi
done

fuzz_total_time="${FUZZ_TOTAL_TIME:-7200}"
per_input_timeout="${FUZZ_PER_INPUT_TIMEOUT:-600}"
worker_spec="${NOBLEFUZZ_WORKERS:-auto}"
guidance_workers="${NOBLEFUZZ_GUIDANCE_WORKERS:-1}"
coverage_seconds="${NOBLEFUZZ_COVERAGE_SECONDS:-30}"
for value_name in FUZZ_MAX_LEN fuzz_total_time per_input_timeout; do
    value="${!value_name}"
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "$value_name must be a positive integer, got: $value" >&2
        exit 1
    fi
done
if [[ ! "$FUZZ_SEED" =~ ^([1-9][0-9]*|0[xX][0-9a-fA-F]{1,64})$ ]] || [[ "$FUZZ_SEED" =~ ^0[xX]0+$ ]]; then
    echo "FUZZ_SEED must be a positive decimal or 0x-prefixed hexadecimal integer of at most 256 bits, got: $FUZZ_SEED" >&2
    exit 1
fi
if [[ ! "$coverage_seconds" =~ ^[0-9]+$ ]]; then
    echo "NOBLEFUZZ_COVERAGE_SECONDS must be a non-negative integer, got: $coverage_seconds" >&2
    exit 1
fi
if [[ ! "$guidance_workers" =~ ^[0-9]+$ ]]; then
    echo "NOBLEFUZZ_GUIDANCE_WORKERS must be a non-negative integer, got: $guidance_workers" >&2
    exit 1
fi
if (( fuzz_total_time < 20 )); then
    echo "FUZZ_TOTAL_TIME must be at least 20 seconds" >&2
    exit 1
fi

case "$NOBLE_MODULE" in
    noble-hashes)
        phases=(digest kdfs argon2)
        shares=(65 30 5)
        operations=(Digest 'HMAC,HKDF,PBKDF2,Scrypt' Argon2)
        corpus_names=(fuzz-corpus-digest fuzz-corpus-kdfs fuzz-corpus-argon2)
        ;;
    noble-ciphers)
        phases=(ciphers)
        shares=(100)
        operations=('SymmetricEncrypt,SymmetricDecrypt')
        corpus_names=(fuzz-corpus)
        ;;
    noble-curves)
        phases=(fast pairing)
        shares=(95 5)
        operations=('ECC,ECDH,ECDSA,Schnorr,BLS,field' 'BLS_Pairing,BLS_FinalExp')
        corpus_names=(fuzz-corpus fuzz-corpus-pairing)
        ;;
    noble-post-quantum)
        phases=(general slh-dsa)
        shares=(80 20)
        operations=('KEM,ML-DSA,Falcon' SLH-DSA)
        corpus_names=(fuzz-corpus fuzz-corpus-slh-dsa)
        ;;
    *)
        echo "noblefuzz does not support module: $NOBLE_MODULE" >&2
        exit 1
        ;;
esac

output_directory="${NOBLEFUZZ_OUTPUT_DIR:-}"
path_in_output() {
    if [[ -n "$output_directory" ]]; then
        echo "$output_directory/$1"
    else
        echo "$1"
    fi
}
artifact_directory="$(path_in_output fuzz-artifacts)"
metadata_file="$artifact_directory/run-metadata.txt"
mkdir -p "$artifact_directory"

phase_times=()
assigned=0
for ((index = 0; index < ${#phases[@]}; index++)); do
    if (( index == ${#phases[@]} - 1 )); then
        seconds=$((fuzz_total_time - assigned))
    else
        seconds=$((fuzz_total_time * shares[index] / 100))
        assigned=$((assigned + seconds))
    fi
    phase_times+=("$seconds")
done

{
    echo "engine=noblefuzz"
    echo "engine_version=2"
    echo "repository=$NOBLE_REPOSITORY"
    echo "source_package=$NOBLE_SOURCE_PACKAGE"
    echo "source_sha=$NOBLE_SOURCE_SHA"
    echo "module=$NOBLE_MODULE"
    echo "seed=$FUZZ_SEED"
    echo "max_total_time=$fuzz_total_time"
    echo "max_len=$FUZZ_MAX_LEN"
    echo "per_input_timeout=$per_input_timeout"
    echo "workers=$worker_spec"
    echo "guidance_workers=$guidance_workers"
    echo "coverage_seconds=$coverage_seconds"
    for ((index = 0; index < ${#phases[@]}; index++)); do
        phase="${phases[index]}"
        echo "${phase}_corpus=$(path_in_output "${corpus_names[index]}")"
        echo "${phase}_max_total_time=${phase_times[index]}"
        echo "${phase}_operations=${operations[index]}"
    done
} > "$metadata_file"

announce() {
    echo "$1"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$1" >> "$GITHUB_STEP_SUMMARY"
    fi
}

run_phase() {
    local phase="$1"
    local corpus="$2"
    local seconds="$3"
    announce "noblefuzz $NOBLE_MODULE phase '$phase' for $seconds seconds with workers=$worker_spec"
    local coverage_args=()
    if (( coverage_seconds > 0 )); then
        coverage_args=(--coverage-seconds "$coverage_seconds")
    fi
    node --no-warnings noblefuzz/cli.mjs fuzz \
        --project "$NOBLE_MODULE" \
        --phase "$phase" \
        --seconds "$seconds" \
        --seed "$FUZZ_SEED" \
        --workers "$worker_spec" \
        --guidance-workers "$guidance_workers" \
        --max-len "$FUZZ_MAX_LEN" \
        --timeout "$per_input_timeout" \
        --corpus "$corpus" \
        --artifacts "$artifact_directory" \
        "${coverage_args[@]}" \
        --source-dir "$NOBLE_SOURCE_DIR"
}

announce "Fuzzing $NOBLE_SOURCE_PACKAGE at $NOBLE_SOURCE_SHA with noblefuzz seed $FUZZ_SEED"
for ((index = 0; index < ${#phases[@]}; index++)); do
    run_phase "${phases[index]}" "$(path_in_output "${corpus_names[index]}")" "${phase_times[index]}"
done
