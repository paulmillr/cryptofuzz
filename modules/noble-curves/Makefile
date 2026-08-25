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
generate_ids.bin : generate_ids.cpp $(REPOSITORY_HEADER)
	$(CXX) $(GENERATOR_CXXFLAGS) generate_ids.cpp -o generate_ids.bin
ids.js : generate_ids.bin
	./generate_ids.bin >ids.js
noble-curves.bytecode : harness.js ids.js package.json package-lock.json build.mjs ../noble-source.mjs
	test $(LIBFUZZER_JS_PATH)
	rm -rf noble-curves.bytecode noble-curves.js
	npm ci && npm run build
	ASAN_OPTIONS=detect_leaks=0 $(LIBFUZZER_JS_PATH)/to_bytecode noble-curves.js noble-curves.bytecode
noble-curves.bytecode.h : noble-curves.bytecode
	node ../../libfuzzer-js/bytecode_to_header.mjs noble-curves.bytecode >noble-curves.bytecode.h
module.o: module.cpp module.h noble-curves.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a noble-curves.js ids.js generate_ids.bin noble-curves.bytecode noble-curves.bytecode.h
