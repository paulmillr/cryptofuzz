# libfuzzer-js

This directory embeds JavaScript in libFuzzer through the vendored QuickJS
runtime. Input is exposed to each harness as the `FuzzerInput` `Uint8Array`.

## Building

Use Clang with libFuzzer support:

```sh
export CC=clang
export CXX=clang++
export LIBFUZZER_A_PATH=-fsanitize=fuzzer
make -C libfuzzer-js
```

The root `build.sh` performs this setup automatically. The Noble adapters are
bundled into single scripts before bytecode compilation, so they do not depend
on QuickJS module loading.

`quickjs/README.cryptofuzz.md` records the vendored runtime provenance and the
coverage instrumentation that must be retained during updates. Build outputs
are intentionally ignored rather than checked into Git.
