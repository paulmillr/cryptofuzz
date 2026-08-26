#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

required_variables=(
    FUZZ_MAX_LEN
    FUZZ_SEED
    NOBLE_MODULE
    NOBLE_REPOSITORY
    NOBLE_SOURCE_PACKAGE
    NOBLE_SOURCE_SHA
)
for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
        echo "Missing required environment variable: $variable" >&2
        exit 1
    fi
done

fuzz_total_time="${FUZZ_TOTAL_TIME:-7200}"
per_input_timeout="${FUZZ_PER_INPUT_TIMEOUT:-600}"
cryptofuzz_bin="${CRYPTOFUZZ_BIN:-$repository_root/cryptofuzz}"

for value_name in FUZZ_MAX_LEN FUZZ_SEED fuzz_total_time per_input_timeout; do
    value="${!value_name}"
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "$value_name must be a positive integer, got: $value" >&2
        exit 1
    fi
done
if (( fuzz_total_time < 100 )); then
    echo "FUZZ_TOTAL_TIME must be at least 100 seconds" >&2
    exit 1
fi
if [[ ! -x "$cryptofuzz_bin" ]]; then
    echo "Cryptofuzz executable not found: $cryptofuzz_bin" >&2
    exit 1
fi

artifact_directory="fuzz-artifacts"
metadata_file="$artifact_directory/run-metadata.txt"
mkdir -p "$artifact_directory"

announce() {
    local message="$1"
    echo "$message"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$message" >> "$GITHUB_STEP_SUMMARY"
    fi
}

record_phase() {
    local name="$1"
    local corpus="$2"
    local seconds="$3"
    local operations="$4"
    local pq_signatures="$5"

    {
        echo "${name}_corpus=$corpus"
        echo "${name}_max_total_time=$seconds"
        echo "${name}_operations=${operations:-build-defaults}"
        echo "${name}_pqsigs=${pq_signatures:-all}"
    } >> "$metadata_file"
}

run_phase() {
    local name="$1"
    local corpus="$2"
    local seconds="$3"
    local operations="$4"
    local pq_signatures="${5:-}"
    local -a arguments=(
        "$corpus"
        "-seed=$FUZZ_SEED"
        "-max_total_time=$seconds"
        "-max_len=$FUZZ_MAX_LEN"
        "-timeout=$per_input_timeout"
        -print_final_stats=1
        "-artifact_prefix=$artifact_directory/"
        "--force-module=$NOBLE_MODULE"
    )

    if [[ -n "$operations" ]]; then
        arguments+=("--only-operations=$operations")
    fi
    if [[ -n "$pq_signatures" ]]; then
        arguments+=("--pqsigs=$pq_signatures")
    fi

    mkdir -p "$corpus"
    record_phase "$name" "$corpus" "$seconds" "$operations" "$pq_signatures"
    announce "Fuzzing $NOBLE_MODULE phase '$name' for $seconds seconds"
    "$cryptofuzz_bin" "${arguments[@]}"
}

{
    echo "repository=$NOBLE_REPOSITORY"
    echo "source_package=$NOBLE_SOURCE_PACKAGE"
    echo "source_sha=$NOBLE_SOURCE_SHA"
    echo "module=$NOBLE_MODULE"
    echo "seed=$FUZZ_SEED"
    echo "max_total_time=$fuzz_total_time"
    echo "max_len=$FUZZ_MAX_LEN"
    echo "per_input_timeout=$per_input_timeout"
} > "$metadata_file"

announce "Fuzzing $NOBLE_MODULE at $NOBLE_SOURCE_SHA with seed $FUZZ_SEED"

case "$NOBLE_MODULE" in
    noble-hashes)
        digest_time=$((fuzz_total_time * 65 / 100))
        kdfs_time=$((fuzz_total_time * 30 / 100))
        argon2_time=$((fuzz_total_time - digest_time - kdfs_time))
        kdfs_operations="HMAC,KDF_HKDF,KDF_PBKDF2,KDF_SCRYPT"

        CRYPTOFUZZ_NOBLE_HASHES_NODE=1 \
            run_phase digest fuzz-corpus-digest "$digest_time" "Digest"
        CRYPTOFUZZ_NOBLE_HASHES_NODE=1 \
            run_phase kdfs fuzz-corpus-kdfs "$kdfs_time" "$kdfs_operations"
        CRYPTOFUZZ_NOBLE_HASHES_NODE=1 \
            run_phase argon2 fuzz-corpus-argon2 "$argon2_time" "KDF_ARGON2"
        ;;
    noble-curves)
        pairing_time=$((fuzz_total_time * 5 / 100))
        fast_time=$((fuzz_total_time - pairing_time))
        fast_operations="ECC_PrivateToPublic,ECC_ValidatePubkey,ECDH_Derive,ECC_Point_Add,ECC_Point_Sub,ECC_Point_Cmp,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg,ECDSA_Sign,ECDSA_Verify,ECDSA_Recover,Schnorr_Sign,Schnorr_Verify,BLS_PrivateToPublic,BLS_PrivateToPublic_G2,BLS_HashToG1,BLS_HashToG2,BLS_MapToG1,BLS_MapToG2,BLS_Sign,BLS_Compress_G1,BLS_Decompress_G1,BLS_Compress_G2,BLS_Decompress_G2,BLS_IsG1OnCurve,BLS_IsG2OnCurve,BLS_G1_Add,BLS_G1_Mul,BLS_G1_Neg,BLS_G1_IsEq,BLS_G1_MultiExp,BLS_G2_Add,BLS_G2_Mul,BLS_G2_Neg,BLS_G2_IsEq,BLS_Aggregate_G1,BLS_Aggregate_G2,BignumCalc"
        pairing_operations="BLS_Verify,BLS_Pairing,BLS_FinalExp"

        run_phase fast fuzz-corpus "$fast_time" "$fast_operations"
        run_phase pairing fuzz-corpus-pairing "$pairing_time" "$pairing_operations"
        ;;
    noble-post-quantum)
        slh_dsa_time=$((fuzz_total_time * 20 / 100))
        general_time=$((fuzz_total_time - slh_dsa_time))
        pq_signature_operations="PQSIG_KeyGen,PQSIG_Sign,PQSIG_Verify"
        general_pq_signatures="ML-DSA-44,ML-DSA-65,ML-DSA-87,Falcon-512,Falcon-1024"
        slh_dsa_signatures="SLH-DSA-SHA2-128f,SLH-DSA-SHA2-128s,SLH-DSA-SHA2-192f,SLH-DSA-SHA2-192s,SLH-DSA-SHA2-256f,SLH-DSA-SHA2-256s,SLH-DSA-SHAKE-128f,SLH-DSA-SHAKE-128s,SLH-DSA-SHAKE-192f,SLH-DSA-SHAKE-192s,SLH-DSA-SHAKE-256f,SLH-DSA-SHAKE-256s"

        run_phase general fuzz-corpus "$general_time" "" "$general_pq_signatures"
        run_phase slh_dsa fuzz-corpus-slh-dsa "$slh_dsa_time" "$pq_signature_operations" "$slh_dsa_signatures"
        ;;
    *)
        run_phase main fuzz-corpus "$fuzz_total_time" ""
        ;;
esac
