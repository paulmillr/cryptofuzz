# CIRCL

The maintained complete build pins Cloudflare CIRCL through
`modules/circl/go.mod` and links it as a native differential oracle. Its
post-quantum coverage overlaps Noble for ML-KEM-512/768/1024, X-Wing,
ML-DSA-44/65/87, and all standardized SHA2/SHAKE SLH-DSA parameter sets.

Build it as part of the complete profile:

```sh
./build.sh
```

The Noble-only profile omits CIRCL and does not require Go.
