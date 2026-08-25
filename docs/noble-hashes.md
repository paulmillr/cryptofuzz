# noble-hashes

`@noble/hashes` is built and tested by the maintained Noble workflow. In
addition to digests, HMAC, HKDF, and PBKDF2, the adapter covers scrypt and
Argon2d/Argon2i/Argon2id through Cryptofuzz's KDF operations. See
[noble cryptography](noble.md).

The adapter passes Noble's Argon2 implementation a 512 MiB `maxmem` limit;
the fuzzed `m` value remains the requested memory cost.
