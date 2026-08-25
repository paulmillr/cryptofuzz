# Dependency policy

Cryptofuzz contains many historical adapters. The supported build path is the
Noble configuration produced by `build.sh`; individual historical modules can
still be built, but they are not automatically linked and should not be assumed
to track their upstream projects.

## Supported toolchains

| Toolchain | Pin | Purpose |
| --- | --- | --- |
| Node.js | `.node-version` | Noble adapters |
| Rust | `rust-toolchain.toml` | Rust adapter validation |
| Go | `.go-version` | CIRCL and maintained Go adapters |

`tools/add.sh` installs the pinned Rust and Go toolchains on x86-64 or arm64 Linux.
It verifies the Go archive checksum before installing it.

## Reproducible dependencies

- Noble package versions are exact in `package.json`; `package-lock.json` and
  `npm ci` lock the complete npm dependency graph. Commit-level CI can
  deliberately override an adapter's primary Noble package with a built
  checkout via `NOBLE_SOURCE_DIR`; this does not modify the adapter manifest or
  lockfile.
- Maintained Go adapters have `go.mod` and `go.sum`; the complete build pins
  CIRCL through the module-local files.
- Rust adapters that compile on stable Rust have checked-in `Cargo.lock` files
  and are validated by `tools/test-rust.sh` with `--locked`.
- LibreSSL, Crypto++, blst, QuickJS, and mpdecimal are pinned in
  `tools/dependencies.sh`. Downloaded release archives are checksum-verified.

The `modules/rustcrypto` aggregate adapter is a legacy exception. It combines
many old, pre-release RustCrypto APIs and moving Git dependencies that are no
longer mutually compatible. It is excluded from `tools/test-rust.sh` until it is
split into focused adapters or ported to one coherent RustCrypto release set.
The other language-specific adapters retain their module-local build
instructions and are outside the supported Noble build profile.

## Updating

Update one dependency family at a time, regenerate its lockfile, and run:

```sh
make test-noble
./tools/test-rust.sh
make -C modules/golang clean all
make -C modules/circl clean all
./build.sh noble
```

For changes to a native oracle or the embedded runtime, also run `./build.sh`
and a short fuzzing smoke test before committing.
