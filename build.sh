#!/usr/bin/env bash

set -Eeuo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_root"

# shellcheck source=tools/dependencies.sh
source "$project_root/tools/dependencies.sh"

mode="${1:-full}"
case "$mode" in
    full)
        fast_build=0
        build_native_modules=1
        ;;
    fast)
        fast_build=1
        build_native_modules=1
        ;;
    noble)
        fast_build=0
        build_native_modules=0
        ;;
    *)
        echo "Usage: $0 [full|fast|noble]" >&2
        exit 1
        ;;
esac

all_noble_modules=(noble-ciphers noble-curves noble-ed25519 noble-hashes noble-post-quantum noble-secp256k1)
noble_modules=("${all_noble_modules[@]}")
if [[ -n "${NOBLE_MODULE:-}" ]]; then
    case "$NOBLE_MODULE" in
        noble-ciphers|noble-curves|noble-ed25519|noble-hashes|noble-post-quantum|noble-secp256k1)
            noble_modules=("$NOBLE_MODULE")
            ;;
        *)
            echo "Unsupported NOBLE_MODULE: $NOBLE_MODULE" >&2
            echo "Expected one of: ${all_noble_modules[*]}" >&2
            exit 1
            ;;
    esac
fi

export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS="${CFLAGS:--fsanitize=address,undefined,fuzzer-no-link -O2 -g}"
export CXXFLAGS="${CXXFLAGS:--fsanitize=address,undefined,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g}"

if (( ! build_native_modules )); then
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"
fi

build_jobs="${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"

missing_tools=()
for required_tool in "$CC" "$CXX" ar cmake curl git make node npm python3 realpath sha256sum tar; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
        missing_tools+=("$required_tool")
    fi
done
if (( build_native_modules )) && ! command -v go >/dev/null 2>&1; then
    missing_tools+=("Go")
fi
if [[ ! -f /usr/include/boost/algorithm/hex.hpp ]]; then
    missing_tools+=("Boost headers")
fi
if (( ${#missing_tools[@]} )); then
    echo "Missing required build tools: ${missing_tools[*]}" >&2
    exit 1
fi

checkout_changed=0
ensure_git_checkout() {
    local directory="$1"
    local repository_url="$2"
    local revision="$3"
    local new_clone=0
    local current_revision
    local actual_url
    local normalized_actual_url
    local normalized_expected_url

    checkout_changed=0
    if [[ ! -d "$directory/.git" ]]; then
        git clone --filter=blob:none --no-checkout "$repository_url" "$directory"
        new_clone=1
    fi

    actual_url="$(git -C "$directory" remote get-url origin)"
    normalized_actual_url="${actual_url%.git}"
    normalized_actual_url="${normalized_actual_url%/}"
    normalized_expected_url="${repository_url%.git}"
    normalized_expected_url="${normalized_expected_url%/}"
    if [[ "$normalized_actual_url" != "$normalized_expected_url" ]]; then
        echo "$directory has unexpected origin: $actual_url" >&2
        exit 1
    fi

    if (( ! new_clone )); then
        if ! git -C "$directory" diff --quiet || ! git -C "$directory" diff --cached --quiet; then
            echo "$directory has tracked changes; refusing to replace them" >&2
            exit 1
        fi
    fi

    current_revision="$(git -C "$directory" rev-parse HEAD 2>/dev/null || true)"
    if (( new_clone )) || [[ "$current_revision" != "$revision" ]]; then
        git -C "$directory" fetch --depth 1 origin "$revision"
        git -C "$directory" checkout --detach "$revision"
        checkout_changed=1
    fi
}

ensure_git_tag() {
    local directory="$1"
    local tag="$2"
    local revision="$3"
    local tag_revision

    tag_revision="$(git -C "$directory" rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)"
    if [[ "$tag_revision" != "$revision" ]]; then
        git -C "$directory" fetch --depth 1 origin "refs/tags/$tag:refs/tags/$tag"
        tag_revision="$(git -C "$directory" rev-parse --verify "refs/tags/$tag^{commit}")"
    fi
    if [[ "$tag_revision" != "$revision" ]]; then
        echo "$directory tag $tag resolves to $tag_revision, expected $revision" >&2
        exit 1
    fi
}

download_verified() {
    local url="$1"
    local output="$2"
    local expected_sha256="$3"
    local temporary_output

    if [[ -f "$output" ]] && printf '%s  %s\n' "$expected_sha256" "$output" | sha256sum -c - >/dev/null 2>&1; then
        return
    fi

    temporary_output="$(mktemp "${output}.tmp.XXXXXX")"
    if ! curl --proto '=https' --tlsv1.2 --fail --show-error --location "$url" -o "$temporary_output"; then
        rm -f -- "$temporary_output"
        exit 1
    fi
    if ! printf '%s  %s\n' "$expected_sha256" "$temporary_output" | sha256sum -c -; then
        rm -f -- "$temporary_output"
        exit 1
    fi
    mv "$temporary_output" "$output"
}

build_fingerprint() {
    printf '%s\n' "$@" | sha256sum | cut -d ' ' -f 1
}

needs_rebuild() {
    local artifact="$1"
    local stamp_file="$2"
    local expected_fingerprint="$3"

    (( ! fast_build )) || [[ ! -f "$artifact" ]] || [[ ! -f "$stamp_file" ]] ||
        [[ "$(<"$stamp_file")" != "$expected_fingerprint" ]]
}

make clean
python3 ./tools/gen_repository.py

module_libraries=()

if (( build_native_modules )); then
    ensure_git_checkout libressl https://github.com/libressl-portable/portable.git "$LIBRESSL_REVISION"
    libressl_changed=$checkout_changed
    ensure_git_tag libressl "$LIBRESSL_VERSION" "$LIBRESSL_REVISION"
    ensure_git_checkout libressl/openbsd https://github.com/libressl/openbsd.git "$LIBRESSL_OPENBSD_REVISION"
    libressl_openbsd_changed=$checkout_changed
    ensure_git_tag libressl/openbsd "libressl-$LIBRESSL_VERSION" "$LIBRESSL_OPENBSD_REVISION"

    libressl_source_fingerprint="$LIBRESSL_REVISION:$LIBRESSL_OPENBSD_REVISION"
    libressl_source_stamp="libressl/.cryptofuzz-source-revision"
    if (( ! fast_build || libressl_changed || libressl_openbsd_changed )) ||
        [[ ! -f "$libressl_source_stamp" ]] || [[ "$(<"$libressl_source_stamp")" != "$libressl_source_fingerprint" ]]; then
        (cd libressl && ./update.sh)
        if [[ "$(git -C libressl/openbsd rev-parse HEAD)" != "$LIBRESSL_OPENBSD_REVISION" ]]; then
            echo "LibreSSL selected an unexpected OpenBSD source revision" >&2
            exit 1
        fi
        printf '%s\n' "$libressl_source_fingerprint" > "$libressl_source_stamp"
    fi

    libressl_fingerprint="$(build_fingerprint "$LIBRESSL_REVISION" "$CC" "$CFLAGS" "$CXXFLAGS")"
    libressl_stamp="libressl/.cryptofuzz-build-config"
    if (( ! fast_build || libressl_changed || libressl_openbsd_changed )) || [[ ! -f "$libressl_stamp" ]] ||
        [[ "$(<"$libressl_stamp")" != "$libressl_fingerprint" ]]; then
        rm -rf -- libressl/build
    fi

    cmake -S libressl -B libressl/build \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="$CFLAGS -fno-sanitize=pointer-overflow" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS"
    cmake --build libressl/build --target crypto --parallel "$build_jobs"
    printf '%s\n' "$libressl_fingerprint" > "$libressl_stamp"

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBRESSL"
    export OPENSSL_INCLUDE_PATH="$(realpath libressl/include)"
    export OPENSSL_LIBCRYPTO_A_PATH="$(realpath libressl/build/crypto/libcrypto.a)"
    export CXXFLAGS="$CXXFLAGS -I $OPENSSL_INCLUDE_PATH -I $(realpath libressl/build/include)"
    make -C modules/openssl clean all
    module_libraries+=(modules/openssl/module.a)

    ensure_git_checkout cryptopp https://github.com/weidai11/cryptopp.git "$CRYPTOPP_REVISION"
    cryptopp_fingerprint="$(build_fingerprint "$CRYPTOPP_REVISION" "$CXX" "$CXXFLAGS")"
    cryptopp_stamp="cryptopp/.cryptofuzz-build-config"
    if needs_rebuild cryptopp/libcryptopp.a "$cryptopp_stamp" "$cryptopp_fingerprint"; then
        make -C cryptopp clean
        make -C cryptopp libcryptopp.a -j"$build_jobs"
        printf '%s\n' "$cryptopp_fingerprint" > "$cryptopp_stamp"
    fi
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
    export LIBCRYPTOPP_A_PATH="$(realpath cryptopp/libcryptopp.a)"
    export CRYPTOPP_INCLUDE_PATH="$(realpath cryptopp)"
    # Module subclasses share the core Module vtable. Rebuild the thin wrapper
    # even in fast mode so a core virtual-method change cannot reuse an
    # ABI-incompatible archive.
    make -C modules/cryptopp clean all
    module_libraries+=(modules/cryptopp/module.a)

    mpdecimal_archive="mpdecimal-${MPDECIMAL_VERSION}.tar.gz"
    mpdecimal_directory="mpdecimal-${MPDECIMAL_VERSION}"
    download_verified \
        "https://www.bytereef.org/software/mpdecimal/releases/$mpdecimal_archive" \
        "$mpdecimal_archive" \
        "$MPDECIMAL_SHA256"
    if [[ ! -d "$mpdecimal_directory" ]]; then
        tar -xzf "$mpdecimal_archive"
    fi
    mpdecimal_fingerprint="$(build_fingerprint "$MPDECIMAL_VERSION" "$CC" "$CXX" "$CFLAGS" "$CXXFLAGS")"
    mpdecimal_stamp="$mpdecimal_directory/.cryptofuzz-build-config"
    if needs_rebuild "$mpdecimal_directory/libmpdec/libmpdec.a" "$mpdecimal_stamp" "$mpdecimal_fingerprint"; then
        (
            cd "$mpdecimal_directory"
            if [[ -f Makefile ]]; then
                make distclean
            fi
            ./configure CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
            make -j"$build_jobs"
        )
        printf '%s\n' "$mpdecimal_fingerprint" > "$mpdecimal_stamp"
    fi
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MPDECIMAL"
    export LIBMPDEC_A_PATH="$(realpath "$mpdecimal_directory/libmpdec/libmpdec.a")"
    export LIBMPDEC_INCLUDE_PATH="$(realpath "$mpdecimal_directory/libmpdec")"
    make -C modules/mpdecimal clean all
    module_libraries+=(modules/mpdecimal/module.a)

    ensure_git_checkout blst https://github.com/supranational/blst.git "$BLST_REVISION"
    blst_fingerprint="$(build_fingerprint "$BLST_REVISION" "$CC" "$CFLAGS")"
    blst_stamp="blst/.cryptofuzz-build-config"
    if needs_rebuild blst/libblst.a "$blst_stamp" "$blst_fingerprint"; then
        (cd blst && ./build.sh)
        printf '%s\n' "$blst_fingerprint" > "$blst_stamp"
    fi
    export BLST_LIBBLST_A_PATH="$(realpath blst/libblst.a)"
    export BLST_INCLUDE_PATH="$(realpath blst/bindings)"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BLST"
    make -C modules/blst clean all
    module_libraries+=(modules/blst/module.a)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CIRCL"
    make -C modules/circl clean all
    module_libraries+=(modules/circl/module.a)
fi

export LIBFUZZER_A_PATH="-fsanitize=fuzzer"
rm -f -- libfuzzer-js/js.o
make -C libfuzzer-js js.o quickjs/libquickjs.a to_bytecode
export LIBFUZZER_JS_PATH="$(realpath libfuzzer-js)"
export LINK_FLAGS="${LINK_FLAGS:-} $LIBFUZZER_JS_PATH/js.o $LIBFUZZER_JS_PATH/quickjs/libquickjs.a"

for noble_module in "${noble_modules[@]}"; do
    noble_define="${noble_module^^}"
    noble_define="${noble_define//-/_}"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_$noble_define"
    make -C "modules/$noble_module" clean all
    module_libraries+=("modules/$noble_module/module.a")
done

export LIBFUZZER_LINK="-fsanitize=fuzzer"

case "${NOBLE_MODULE:-}" in
    noble-ciphers)
        default_options="--operations=SymmetricEncrypt,SymmetricDecrypt --ciphers=AES_128_ECB,AES_192_ECB,AES_256_ECB,AES_128_CBC,AES_192_CBC,AES_256_CBC,AES_128_CTR,AES_192_CTR,AES_256_CTR,AES_128_CFB,AES_192_CFB,AES_256_CFB,AES_128_CFB128,AES_192_CFB128,AES_256_CFB128,AES_128_GCM,AES_192_GCM,AES_256_GCM,AES_128_GCM_SIV,AES_256_GCM_SIV,AES_128_SIV_CMAC,AES_192_SIV_CMAC,AES_256_SIV_CMAC,AES_128_WRAP,AES_192_WRAP,AES_256_WRAP,AES_128_WRAP_PAD,AES_192_WRAP_PAD,AES_256_WRAP_PAD,CHACHA20,CHACHA20_POLY1305,XCHACHA20_POLY1305,SALSA20_128,SALSA20_256"
        ;;
    noble-curves)
        default_options="--operations=ECC_PrivateToPublic,ECC_ValidatePubkey,ECDH_Derive,ECC_Point_Add,ECC_Point_Sub,ECC_Point_Cmp,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg,ECDSA_Sign,ECDSA_Verify,ECDSA_Recover,Schnorr_Sign,Schnorr_Verify,BLS_PrivateToPublic,BLS_PrivateToPublic_G2,BLS_HashToG1,BLS_HashToG2,BLS_MapToG1,BLS_MapToG2,BLS_Sign,BLS_Verify,BLS_Pairing,BLS_FinalExp,BLS_Compress_G1,BLS_Decompress_G1,BLS_Compress_G2,BLS_Decompress_G2,BLS_IsG1OnCurve,BLS_IsG2OnCurve,BLS_G1_Add,BLS_G1_Mul,BLS_G1_Neg,BLS_G1_IsEq,BLS_G1_MultiExp,BLS_G2_Add,BLS_G2_Mul,BLS_G2_Neg,BLS_G2_IsEq,BLS_Aggregate_G1,BLS_Aggregate_G2,BignumCalc --curves=secp256r1,secp384r1,secp521r1,secp256k1,brainpool256r1,brainpool384r1,brainpool512r1,ed25519,ed448,x25519,x448,bls12_381,alt_bn128 --digests=NULL,SHA256,SHA384,SHA512"
        ;;
    noble-ed25519)
        default_options="--operations=ECC_PrivateToPublic,ECDSA_Sign,ECDSA_Verify --curves=ed25519 --digests=NULL,SHA256"
        ;;
    noble-hashes)
        default_options="--operations=Digest,HMAC,KDF_HKDF,KDF_PBKDF2,KDF_SCRYPT,KDF_ARGON2 --digests=MD5,SHA1,SHA224,SHA256,SHA384,SHA512,SHA512-224,SHA512-256,RIPEMD160,BLAKE2S128,BLAKE2S160,BLAKE2S224,BLAKE2S256,BLAKE2B128,BLAKE2B160,BLAKE2B256,BLAKE2B384,BLAKE2B512,BLAKE3,SHA3-224,SHA3-256,SHA3-384,SHA3-512,KECCAK_224,KECCAK_256,KECCAK_384,KECCAK_512,SHAKE128,SHAKE256,SHAKE256_114"
        ;;
    noble-post-quantum)
        default_options="--operations=KEM_KeyGen,KEM_Encapsulate,KEM_Decapsulate,PQSIG_KeyGen,PQSIG_Sign,PQSIG_Verify"
        ;;
    noble-secp256k1)
        default_options="--operations=ECC_PrivateToPublic,ECDSA_Sign,ECDSA_Verify,ECC_Point_Add,ECC_Point_Mul,ECC_Point_Neg,ECC_Point_Dbl --curves=secp256k1 --digests=NULL,SHA256"
        ;;
    *)
        default_options="--operations=Digest,HMAC,KDF_HKDF,KDF_PBKDF2,KDF_SCRYPT,KDF_ARGON2,SymmetricEncrypt,SymmetricDecrypt,ECC_PrivateToPublic,ECC_ValidatePubkey,ECDH_Derive,ECC_Point_Add,ECC_Point_Sub,ECC_Point_Cmp,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg,ECDSA_Sign,ECDSA_Verify,ECDSA_Recover,Schnorr_Sign,Schnorr_Verify,BLS_PrivateToPublic,BLS_PrivateToPublic_G2,BLS_HashToG1,BLS_HashToG2,BLS_MapToG1,BLS_MapToG2,BLS_Sign,BLS_Verify,BLS_Pairing,BLS_FinalExp,BLS_Compress_G1,BLS_Decompress_G1,BLS_Compress_G2,BLS_Decompress_G2,BLS_IsG1OnCurve,BLS_IsG2OnCurve,BLS_G1_Add,BLS_G1_Mul,BLS_G1_Neg,BLS_G1_IsEq,BLS_G1_MultiExp,BLS_G2_Add,BLS_G2_Mul,BLS_G2_Neg,BLS_G2_IsEq,BLS_Aggregate_G1,BLS_Aggregate_G2,KEM_KeyGen,KEM_Encapsulate,KEM_Decapsulate,PQSIG_KeyGen,PQSIG_Sign,PQSIG_Verify,BignumCalc --curves=secp192r1,secp224r1,secp256r1,secp384r1,secp521r1,secp256k1,brainpool256r1,brainpool384r1,brainpool512r1,ed25519,ed448,x25519,x448,bls12_381,alt_bn128 --digests=NULL,MD5,SHA1,SHA224,SHA256,SHA384,SHA512,SHA512-224,SHA512-256,RIPEMD160,BLAKE2S128,BLAKE2S160,BLAKE2S224,BLAKE2S256,BLAKE2B128,BLAKE2B160,BLAKE2B256,BLAKE2B384,BLAKE2B512,BLAKE3,SHA3-224,SHA3-256,SHA3-384,SHA3-512,KECCAK_224,KECCAK_256,KECCAK_384,KECCAK_512,SHAKE128,SHAKE256,SHAKE256_114"
        ;;
esac
printf '"%s"\n' "$default_options" > src/extra_options.h

make -j"$build_jobs" \
    BUILD_JOBS="$build_jobs" \
    MODULE_LIBRARIES="${module_libraries[*]}"

echo "Built cryptofuzz in $mode mode with: ${module_libraries[*]}"
