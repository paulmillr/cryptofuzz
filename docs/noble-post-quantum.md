# noble-post-quantum

`@noble/post-quantum` is built and tested by the maintained Noble workflow. It
implements deterministic fuzzing operations for key generation,
encapsulation/decapsulation, and signing/verification.

The KEM surface covers ML-KEM-512/768/1024, X-Wing, and Noble's ML-KEM hybrid
presets. The signature surface covers ML-DSA-44/65/87, every standardized
SHA2/SHAKE SLH-DSA parameter set, and Falcon-512/1024. The complete build links
CIRCL as an independent oracle for the overlapping ML-KEM, X-Wing, ML-DSA, and
SLH-DSA algorithms.

See [noble cryptography](noble.md) for the supported build commands and pinned
version policy.
