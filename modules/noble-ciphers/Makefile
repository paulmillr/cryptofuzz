.PHONY: all clean test

all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
GENERATOR_CXXFLAGS = $(filter-out -fsanitize=%,$(CXXFLAGS))
REPOSITORY_HEADER = ../../repository_tbl.h

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
$(REPOSITORY_HEADER): ../../tools/gen_repository.py
	$(MAKE) -C ../.. repository_tbl.h
generate_ids.bin: generate_ids.cpp $(REPOSITORY_HEADER)
	$(CXX) $(GENERATOR_CXXFLAGS) generate_ids.cpp -o generate_ids.bin
ids.js: generate_ids.bin
	./generate_ids.bin >ids.js
noble-ciphers.js: harness.js ids.js package.json package-lock.json build.mjs ../noble-source.mjs
	npm ci && npm run build
noble-ciphers.bytecode: noble-ciphers.js
	test $(LIBFUZZER_JS_PATH)
	rm -f noble-ciphers.bytecode
	ASAN_OPTIONS=detect_leaks=0 $(LIBFUZZER_JS_PATH)/to_bytecode noble-ciphers.js noble-ciphers.bytecode
noble-ciphers.bytecode.h: noble-ciphers.bytecode
	node ../../libfuzzer-js/bytecode_to_header.mjs noble-ciphers.bytecode >noble-ciphers.bytecode.h
module.o: module.cpp module.h noble-ciphers.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
test: ids.js
	npm test
clean:
	rm -rf *.o module.a ids.js generate_ids.bin noble-ciphers.js noble-ciphers.bytecode noble-ciphers.bytecode.h
