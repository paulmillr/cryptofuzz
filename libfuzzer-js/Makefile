.PHONY: all clean quickjs/libquickjs.a

all : jsfuzzer to_bytecode

js.o : js.cpp js.h
	$(CXX) $(CXXFLAGS) -std=c++17 -g -I quickjs/ -fsanitize=fuzzer-no-link js.cpp -c -o js.o

quickjs/libquickjs.a :
	CFLAGS="$(CFLAGS) -fno-sanitize=all" \
		$(MAKE) -C quickjs CONFIG_CLANG=y CC="$(CC)" libquickjs.a

jsfuzzer : harness.cpp js.o quickjs/libquickjs.a
	test $(LIBFUZZER_A_PATH)
	$(CXX) $(CXXFLAGS) -std=c++17 harness.cpp js.o quickjs/libquickjs.a $(LIBFUZZER_A_PATH) -ldl -lm -lpthread -o jsfuzzer

to_bytecode : to_bytecode.cpp js.o quickjs/libquickjs.a
	$(CXX) $(CXXFLAGS) -std=c++17 -fsanitize=fuzzer-no-link to_bytecode.cpp js.o quickjs/libquickjs.a -ldl -lm -o to_bytecode

clean:
	rm -f js.o jsfuzzer to_bytecode
	$(MAKE) -C quickjs clean
