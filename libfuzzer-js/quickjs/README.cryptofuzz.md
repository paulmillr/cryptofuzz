# Vendored QuickJS

This is the minimal QuickJS source set needed by `libfuzzer-js`. It was
vendored from the official QuickJS repository at the revision recorded as
`QUICKJS_REVISION` in `tools/dependencies.sh`.

Cryptofuzz adds a libFuzzer extra-counter section and increments it at
interpreted function entries and branch destinations. This provides
JavaScript basic-block coverage without adding work to every bytecode
dispatch, which is prohibitively expensive for cryptographic inner loops.
The parent Makefile therefore builds QuickJS without compiler sanitizers; the
surrounding Cryptofuzz engine remains sanitized, and the manual counters retain
JavaScript coverage. It also uses a correctly typed allocator thunk where
upstream casts `js_realloc_rt`, avoiding function-type sanitizer errors. Keep
these changes when updating the vendored runtime. Generated objects, archives,
and executables are not tracked.
