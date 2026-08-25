#!/usr/bin/env bash

set -Eeuo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

make -C modules/ring src/ids.rs

rust_modules=(
    aleo
    arkworks-algebra
    aurora-engine-modexp
    ff
    k256
    num-bigint
    pairing_ce
    pasta_curves
    ring
    rust-libsecp256k1
    schnorr_fun
    schnorrkel
    spl_math
    substrate-bn
    tiny-keccak
)

for rust_module in "${rust_modules[@]}"; do
    echo "Checking modules/$rust_module"
    cargo check --locked --manifest-path "modules/$rust_module/Cargo.toml"
done
