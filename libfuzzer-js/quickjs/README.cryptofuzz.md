# Vendored QuickJS

This is the minimal QuickJS source set needed by `libfuzzer-js`. It was
vendored from the official QuickJS repository at the revision recorded as
`QUICKJS_REVISION` in `tools/dependencies.sh`.

Cryptofuzz adds a libFuzzer extra-counter section and increments it for every
interpreted bytecode instruction. It also uses a correctly typed allocator
thunk where upstream casts `js_realloc_rt`, avoiding function-type sanitizer
errors. Keep both changes when updating the vendored runtime. Generated
objects, archives, and executables are not tracked.
