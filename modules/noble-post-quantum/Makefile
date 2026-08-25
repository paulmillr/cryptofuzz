.PHONY: all clean

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
noble-post-quantum.bytecode: harness.js ids.js package.json package-lock.json build.mjs ../noble-source.mjs
	test $(LIBFUZZER_JS_PATH)
	rm -f noble-post-quantum.bytecode noble-post-quantum.js
	npm ci && npm run build
	ASAN_OPTIONS=detect_leaks=0 $(LIBFUZZER_JS_PATH)/to_bytecode noble-post-quantum.js noble-post-quantum.bytecode
noble-post-quantum.bytecode.h: noble-post-quantum.bytecode
	node ../../libfuzzer-js/bytecode_to_header.mjs noble-post-quantum.bytecode >noble-post-quantum.bytecode.h
module.o: module.cpp module.h noble-post-quantum.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -f *.o module.a ids.js generate_ids.bin noble-post-quantum.js noble-post-quantum.bytecode noble-post-quantum.bytecode.h
