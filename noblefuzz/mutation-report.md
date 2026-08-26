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

## Mutation score

| Project | Version | Commit | Detected | Distinct classes | Survived |
| --- | --- | --- | ---: | ---: | ---: |
| noble-ciphers | 2.3.0 | `5053f9059ad9c6881583c900b6d212de4d5444b4` | 21/21 | 21 | 0 |
| noble-curves | 2.3.0 | `d5b95e489a418b1deb7862755dda5ef0db342acb` | 20/20 | 20 | 0 |
| noble-hashes | 2.3.0 | `a169e0961b17c91025af1b4ecb7a14a10822b142` | 18/18 | 18 | 0 |
| noble-post-quantum | 0.7.0 | `cf4cc8f7babca87566711c0624ac20f398e2be79` | 19/19 | 19 | 0 |

Total: **78/78 detected**, 0 survived.

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
| `gcm-length-block-order` | GCM authenticated length encoding | ciphers | startup |
| `gcm-siv-counter-domain-bit` | GCM-SIV counter domain bit | ciphers | startup |
| `gcm-tag-verification-bypass` | AEAD authentication bypass | ciphers | testcase |
| `ghash-reduction-polynomial` | GHASH reduction polynomial | ciphers | startup |
| `ghash-key-endian` | GHASH key word endianness | ciphers | startup |
| `poly1305-clamp-mask` | Poly1305 key clamping | ciphers | testcase |
| `poly1305-full-block-bit` | Poly1305 full-block high bit | ciphers | testcase |
| `arx-round-count` | ARX stream-cipher round count | ciphers | startup |
| `chacha-quarter-rotation` | ChaCha quarter-round rotation | ciphers | testcase |
| `chacha-quarter-addition` | ChaCha add/xor operation | ciphers | testcase |
| `hchacha-subkey-word` | HChaCha subkey word selection | ciphers | testcase |
| `salsa-feedforward-operation` | Salsa feed-forward operation | ciphers | startup |
| `xsalsa-tag-verification-bypass` | Secretbox authentication bypass | ciphers | startup |

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
| `ed25519-curve-d` | twisted-Edwards curve coefficient | fast | startup |
| `ed25519-scalar-low-clamp` | Ed25519/X25519 low-bit scalar clamping | fast | testcase |
| `ed25519-scalar-high-clamp` | Ed25519/X25519 high-bit scalar clamping | fast | startup |
| `eddsa-sign-equation` | EdDSA signature scalar equation | fast | testcase |
| `eddsa-verify-bypass` | EdDSA signature verification bypass | fast | testcase |
| `montgomery-ladder-constant` | Montgomery ladder a24 constant | fast | testcase |
| `montgomery-differential-add` | Montgomery differential-addition formula | fast | testcase |
| `bls-g2-wire-order` | BLS G2 component serialization order | fast | testcase |
| `bls-miller-loop-size` | BLS12-381 Miller-loop parameter | pairing | testcase |
| `bls-miller-loop-sign` | BLS12-381 Miller-loop sign | pairing | testcase |
| `bn254-miller-loop-size` | BN254 Miller-loop parameter | pairing | testcase |
| `bn254-tower-nonresidue` | BN254 extension-field nonresidue | pairing | testcase |

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
| `sha1-message-endian` | legacy digest endianness | digest | testcase |
| `md5-message-endian` | little-endian digest decoding | digest | testcase |
| `hmac-ipad` | HMAC domain-separation pad | kdfs | testcase |
| `hkdf-block-counter` | HKDF expansion counter | kdfs | testcase |
| `pbkdf2-counter-endian` | PBKDF2 block counter encoding | kdfs | testcase |
| `pbkdf2-fold-operation` | PBKDF2 iteration folding | kdfs | testcase |
| `scrypt-salsa-rotation` | scrypt Salsa20/8 rotation | kdfs | testcase |
| `argon2-final-lane` | Argon2 lane finalization | argon2 | testcase |

## noble-post-quantum

| Mutation | Defect class | Phase | Detection |
| --- | --- | --- | --- |
| `ml-kem-modulus` | ML-KEM polynomial modulus | general | testcase |
| `ml-kem-root-of-unity` | ML-KEM NTT root of unity | general | testcase |
| `ml-kem-inverse-factor` | ML-KEM inverse-NTT normalization | general | testcase |
| `ml-kem-compression-rounding` | ML-KEM coefficient compression rounding | general | testcase |
| `ml-kem-base-multiply` | ML-KEM base-case multiplication | general | testcase |
| `ml-kem-matrix-sampling` | ML-KEM rejection-sampling byte assembly | general | testcase |
| `ml-kem-cbd-sign` | ML-KEM centered-binomial noise sign | general | testcase |
| `ml-kem-keygen-domain` | ML-KEM parameter-set keygen domain | general | testcase |
| `ml-kem-encapsulation-transcript` | ML-KEM encapsulation transcript binding | general | testcase |
| `ml-kem-secret-selection` | ML-KEM implicit-rejection secret selection | general | testcase |
| `ml-dsa-rejection-mask` | ML-DSA rejection-sampling candidate mask | general | testcase |
| `ml-dsa-use-hint` | ML-DSA hint reconstruction direction | general | testcase |
| `ml-dsa-keygen-domain` | ML-DSA parameter-set keygen domain | general | testcase |
| `ml-dsa-commitment-transcript` | ML-DSA commitment transcript binding | general | testcase |
| `ml-dsa-verify-bypass` | ML-DSA signature verification bypass | general | testcase |
| `falcon-hash-nonce` | Falcon nonce transcript binding | general | testcase |
| `falcon-hash-rejection-bound` | Falcon hash-to-point rejection bound | general | testcase |
| `falcon-verification-equation` | Falcon verification polynomial equation | general | testcase |
| `falcon-norm-bypass` | Falcon signature norm-check bypass | general | testcase |

