# noblefuzz mutation campaign

Generated from 1 machine-readable report. A mutation counts only when the fuzzer exits on a concrete startup or testcase failure; watchdog and process timeouts are not credited.

## Clean baselines

| Project | Phase | Seed | Result |
| --- | --- | ---: | --- |
| noble-hashes | digest | 1297437761 | passed |
| noble-hashes | kdfs | 1297437761 | passed |
| noble-hashes | argon2 | 1297437761 | passed |
| noble-ciphers | ciphers | 1297437761 | passed |
| noble-curves | fast | 1297437761 | passed |
| noble-curves | pairing | 1297437761 | passed |
| noble-post-quantum | general | 1297437761 | passed |
| noble-post-quantum | slh-dsa | 1297437761 | passed |

## Mutation score

| Project | Version | Commit | Detected | Distinct classes | Survived |
| --- | --- | --- | ---: | ---: | ---: |
| noble-ciphers | 2.3.0 | `5053f9059ad9c6881583c900b6d212de4d5444b4` | 37/37 | 37 | 0 |
| noble-curves | 2.3.0 | `d5b95e489a418b1deb7862755dda5ef0db342acb` | 38/38 | 38 | 0 |
| noble-hashes | 2.3.0 | `a169e0961b17c91025af1b4ecb7a14a10822b142` | 34/34 | 34 | 0 |
| noble-post-quantum | 0.7.0 | `cf4cc8f7babca87566711c0624ac20f398e2be79` | 38/38 | 38 | 0 |

Total: **147/147 detected**, 0 survived.

## noble-ciphers

| Mutation | Defect class | Phase | Detection |
| --- | --- | --- | --- |
| `aes-field-polynomial` | AES field reduction polynomial | ciphers | startup |
| `aes-sbox-affine-constant` | AES S-box affine constant | ciphers | startup |
| `aes-rcon-sequence` | AES key-schedule round constants | ciphers | startup |
| `aes-rotword-direction` | AES key-schedule word rotation | ciphers | startup |
| `aes-encryption-round-count` | AES encryption round count | ciphers | startup |
| `aes-shiftrows-lane-order` | AES ShiftRows lane order | ciphers | startup |
| `aes-mixcolumns-coefficient` | AES MixColumns coefficient | ciphers | startup |
| `aes-ctr-counter-direction` | CTR counter byte order | ciphers | testcase |
| `aes-cbc-chaining-xor` | CBC plaintext chaining operation | ciphers | testcase |
| `aes-cbc-padding-check` | CBC PKCS#7 padding validation | ciphers | testcase |
| `aes-cfb-feedback-source` | CFB decrypt feedback selection | ciphers | testcase |
| `gcm-length-block-order` | GCM authenticated length encoding | ciphers | startup |
| `gcm-aad-binding` | GCM associated-data authentication | ciphers | testcase |
| `gcm-j0-counter` | GCM initial counter block | ciphers | startup |
| `gcm-siv-counter-domain-bit` | GCM-SIV counter domain bit | ciphers | startup |
| `gcm-tag-verification-bypass` | AEAD authentication bypass | ciphers | testcase |
| `ghash-reduction-polynomial` | GHASH reduction polynomial | ciphers | startup |
| `ghash-key-endian` | GHASH key word endianness | ciphers | startup |
| `poly1305-clamp-mask` | Poly1305 key clamping | ciphers | startup |
| `poly1305-full-block-bit` | Poly1305 full-block high bit | ciphers | startup |
| `poly1305-final-reduction` | Poly1305 canonical modular reduction | ciphers | startup |
| `arx-round-count` | ARX stream-cipher round count | ciphers | startup |
| `chacha-quarter-rotation` | ChaCha quarter-round rotation | ciphers | startup |
| `chacha-quarter-addition` | ChaCha add/xor operation | ciphers | startup |
| `hchacha-subkey-word` | HChaCha subkey word selection | ciphers | startup |
| `salsa-feedforward-operation` | Salsa feed-forward operation | ciphers | startup |
| `xsalsa-tag-verification-bypass` | Secretbox authentication bypass | ciphers | startup |
| `chacha-aead-aad-binding` | ChaCha AEAD associated-data authentication | ciphers | startup |
| `chacha-aead-payload-counter` | ChaCha AEAD payload counter separation | ciphers | testcase |
| `aes-wrap-round-count` | AES key-wrap transform round count | ciphers | testcase |
| `aes-wrap-iv-check` | AES-KW integrity-value validation | ciphers | testcase |
| `aes-wrap-pad-zero-check` | AES-KWP recovered padding validation | ciphers | startup |
| `aes-cmac-full-block-subkey` | CMAC final-block subkey selection | ciphers | startup |
| `aes-cmac-padding-bit` | CMAC partial-block padding delimiter | ciphers | startup |
| `aes-s2v-component-doubling` | S2V component chaining | ciphers | startup |
| `aes-siv-ctr-bit-clearing` | AES-SIV counter bit masking | ciphers | startup |
| `aes-siv-tag-verification` | AES-SIV authentication validation | ciphers | testcase |

## noble-curves

| Mutation | Defect class | Phase | Detection |
| --- | --- | --- | --- |
| `secp256k1-field-modulus` | prime-field modulus | fast | startup |
| `secp256k1-generator-y` | base-point coordinate | fast | startup |
| `schnorr-tag-prefix` | Schnorr tagged-hash prefix | fast | testcase |
| `schnorr-challenge-domain` | Schnorr challenge domain tag | fast | testcase |
| `p256-curve-coefficient` | short-Weierstrass curve coefficient | fast | startup |
| `p256-signature-hash` | ECDSA message hash selection | fast | testcase |
| `ecdsa-sign-equation` | ECDSA signature scalar equation | fast | testcase |
| `ecdsa-verify-u2` | ECDSA verification scalar equation | fast | testcase |
| `weierstrass-compressed-parity` | SEC1 compressed-point parity encoding | fast | testcase |
| `ecdh-peer-key-binding` | ECDH peer public-key contribution | fast | testcase |
| `ecdsa-low-s-normalization` | ECDSA low-S canonicalization | fast | testcase |
| `ecdsa-recovery-parity` | ECDSA public-key recovery parity bit | fast | testcase |
| `ed25519-curve-d` | twisted-Edwards curve coefficient | fast | startup |
| `ed25519-scalar-low-clamp` | Ed25519/X25519 low-bit scalar clamping | fast | startup |
| `ed25519-scalar-high-clamp` | Ed25519/X25519 high-bit scalar clamping | fast | testcase |
| `eddsa-sign-equation` | EdDSA signature scalar equation | fast | testcase |
| `eddsa-verify-bypass` | EdDSA signature verification bypass | fast | testcase |
| `edwards-encoded-x-sign` | Edwards compressed-point sign decoding | fast | testcase |
| `eddsa-public-key-transcript` | EdDSA challenge public-key binding | fast | testcase |
| `ristretto255-quotient-encoding` | Ristretto255 canonical quotient encoding | fast | startup |
| `decaf448-quotient-encoding` | Decaf448 canonical quotient encoding | fast | startup |
| `montgomery-ladder-constant` | Montgomery ladder a24 constant | fast | testcase |
| `montgomery-differential-add` | Montgomery differential-addition formula | fast | testcase |
| `bls-g2-wire-order` | BLS G2 component serialization order | fast | startup |
| `bls-compressed-sort-bit` | BLS compressed-point sign-bit calculation | fast | startup |
| `bls-g1-hash-domain` | BLS G1 hash-to-curve suite domain | fast | startup |
| `bls-g2-hash-domain` | BLS G2 hash-to-curve suite domain | fast | startup |
| `bls-g1-subgroup-endomorphism` | BLS G1 subgroup endomorphism constant | fast | startup |
| `bls-g2-subgroup-endomorphism` | BLS G2 subgroup endomorphism relation | fast | startup |
| `hash-to-curve-dst-length` | hash-to-curve DST length binding | fast | startup |
| `hash-to-curve-cofactor` | hash-to-curve cofactor clearing | fast | startup |
| `bls-miller-loop-size` | BLS12-381 Miller-loop parameter | pairing | testcase |
| `bls-miller-loop-sign` | BLS12-381 Miller-loop sign | pairing | testcase |
| `bls-final-exponent-chain` | BLS12-381 final-exponentiation addition chain | pairing | testcase |
| `bn254-miller-loop-size` | BN254 Miller-loop parameter | pairing | testcase |
| `bn254-tower-nonresidue` | BN254 extension-field nonresidue | pairing | testcase |
| `bn254-g2-subgroup-equation` | BN254 G2 subgroup relation | fast | startup |
| `bn254-final-exponent-chain` | BN254 final-exponentiation addition chain | pairing | testcase |

## noble-hashes

| Mutation | Defect class | Phase | Detection |
| --- | --- | --- | --- |
| `sha256-message-endian` | message word endianness | digest | testcase |
| `sha256-schedule-rotation` | message schedule rotation | digest | testcase |
| `sha256-choice-function` | round boolean function | digest | testcase |
| `sha256-round-count` | compression round count | digest | testcase |
| `sha512-low-word-offset` | 64-bit word assembly | digest | testcase |
| `sha3-lfsr-mask` | round constant generation | digest | testcase |
| `sha3-pi-lane` | lane permutation | digest | testcase |
| `sha3-rotation-offset` | lane rotation schedule | digest | testcase |
| `sha3-chi-gate` | nonlinear boolean gate | digest | testcase |
| `blake3-round-count` | tree hash round count | digest | startup |
| `blake2b-counter-low-word` | BLAKE2b byte-counter injection | digest | testcase |
| `blake2b-final-flag` | BLAKE2b final-block domain flag | digest | testcase |
| `blake2s-round-count` | BLAKE2s compression round count | digest | testcase |
| `blake2s-final-flag` | BLAKE2s final-block domain flag | digest | testcase |
| `blake3-chunk-start-flag` | BLAKE3 leaf-start domain flag | digest | startup |
| `blake3-parent-flag` | BLAKE3 parent-node domain flag | digest | startup |
| `blake3-root-flag` | BLAKE3 root-output domain flag | digest | startup |
| `sha1-message-endian` | legacy digest endianness | digest | testcase |
| `md5-message-endian` | little-endian digest decoding | digest | testcase |
| `hmac-ipad` | HMAC domain-separation pad | kdfs | testcase |
| `hmac-opad` | HMAC outer domain-separation pad | kdfs | testcase |
| `hkdf-block-counter` | HKDF expansion counter | kdfs | testcase |
| `hkdf-extract-key-role` | HKDF extract salt/input roles | kdfs | testcase |
| `hkdf-info-binding` | HKDF expand info binding | kdfs | testcase |
| `pbkdf2-counter-endian` | PBKDF2 block counter encoding | kdfs | testcase |
| `pbkdf2-fold-operation` | PBKDF2 iteration folding | kdfs | testcase |
| `scrypt-salsa-rotation` | scrypt Salsa20/8 rotation | kdfs | testcase |
| `scrypt-integerify-word` | scrypt ROMix Integerify selection | kdfs | testcase |
| `argon2-final-lane` | Argon2 lane finalization | argon2 | testcase |
| `argon2-version-xor-rule` | Argon2 v1.3 overwrite/XOR rule | argon2 | testcase |
| `argon2id-addressing-window` | Argon2id addressing-mode cutoff | argon2 | testcase |
| `argon2-reference-index` | Argon2 reference-block index mapping | argon2 | testcase |
| `shake128-domain-suffix` | SHAKE domain-separation suffix | digest | testcase |
| `ripemd160-message-endian` | RIPEMD-160 message word endianness | digest | testcase |

## noble-post-quantum

| Mutation | Defect class | Phase | Detection |
| --- | --- | --- | --- |
| `ml-kem-modulus` | ML-KEM polynomial modulus | general | startup |
| `ml-kem-root-of-unity` | ML-KEM NTT root of unity | general | startup |
| `ml-kem-inverse-factor` | ML-KEM inverse-NTT normalization | general | startup |
| `ml-kem-compression-rounding` | ML-KEM coefficient compression rounding | general | startup |
| `ml-kem-base-multiply` | ML-KEM base-case multiplication | general | startup |
| `ml-kem-matrix-sampling` | ML-KEM rejection-sampling byte assembly | general | startup |
| `ml-kem-cbd-sign` | ML-KEM centered-binomial noise sign | general | startup |
| `ml-kem-keygen-domain` | ML-KEM parameter-set keygen domain | general | startup |
| `ml-kem-encapsulation-transcript` | ML-KEM encapsulation transcript binding | general | startup |
| `ml-kem-secret-selection` | ML-KEM implicit-rejection secret selection | general | testcase |
| `ml-kem-public-modulus-check` | ML-KEM public-key modulus validation | general | startup |
| `ml-kem-secret-hash-check` | ML-KEM decapsulation-key hash validation | general | startup |
| `hybrid-ecdh-output-format` | hybrid ECDH shared-secret encoding | general | startup |
| `hybrid-seed-expansion-length` | hybrid component seed expansion | general | startup |
| `qsf-combiner-order` | QSF hybrid combiner transcript order | general | startup |
| `kitchen-sink-ciphertext-binding` | KitchenSink hybrid ciphertext binding | general | startup |
| `xwing-domain-label` | X-Wing hybrid combiner domain label | general | startup |
| `nist-hybrid-coordinate-binding` | NIST hybrid shared-point coordinate binding | general | startup |
| `ml-dsa-rejection-mask` | ML-DSA rejection-sampling candidate mask | general | startup |
| `ml-dsa-use-hint` | ML-DSA hint reconstruction direction | general | testcase |
| `ml-dsa-keygen-domain` | ML-DSA parameter-set keygen domain | general | startup |
| `ml-dsa-commitment-transcript` | ML-DSA commitment transcript binding | general | startup |
| `ml-dsa-verify-bypass` | ML-DSA signature verification bypass | general | testcase |
| `ml-dsa-response-norm` | ML-DSA response-vector norm bound | general | startup |
| `ml-dsa-hint-count-bound` | ML-DSA hint-weight bound | general | startup |
| `ml-dsa-context-binding` | ML-DSA context transcript binding | general | startup |
| `slh-dsa-wots-checksum` | SLH-DSA WOTS checksum complement | slh-dsa | testcase |
| `slh-dsa-auth-path-sibling` | SLH-DSA tree authentication sibling selection | slh-dsa | testcase |
| `slh-dsa-root-node-order` | SLH-DSA Merkle node ordering | slh-dsa | testcase |
| `slh-dsa-hypertree-shift` | SLH-DSA hypertree layer progression | slh-dsa | testcase |
| `slh-dsa-wots-chain-length` | SLH-DSA WOTS verification chain length | slh-dsa | testcase |
| `slh-dsa-root-verification` | SLH-DSA public-root comparison | slh-dsa | testcase |
| `falcon-hash-nonce` | Falcon nonce transcript binding | general | testcase |
| `falcon-hash-rejection-bound` | Falcon hash-to-point rejection bound | general | testcase |
| `falcon-verification-equation` | Falcon verification polynomial equation | general | testcase |
| `falcon-norm-bypass` | Falcon signature norm-check bypass | general | testcase |
| `falcon-coefficient-sign-encoding` | Falcon compressed coefficient sign bit | general | testcase |
| `falcon-coefficient-low-bits` | Falcon compressed coefficient low-bit packing | general | testcase |

