# Building libfuzzer-js

This is required for fuzzing JavaScript libraries.

The maintained bridge is vendored in this repository, so no separate clone is
needed:

```sh
export LIBFUZZER_A_PATH="-fsanitize=fuzzer"
cd libfuzzer-js/
make
export LIBFUZZER_JS_PATH=$(realpath .)
export LINK_FLAGS="${LINK_FLAGS:-} $LIBFUZZER_JS_PATH/js.o $LIBFUZZER_JS_PATH/quickjs/libquickjs.a"
cd ../
```
