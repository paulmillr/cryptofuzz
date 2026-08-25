.PHONY: all clean test-noble

all : cryptofuzz generate_dict generate_corpus

CXXFLAGS += -Wall -Wextra -std=c++17 -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
BUILD_JOBS ?= $(shell nproc 2>/dev/null || echo 1)
MODULE_LIBRARIES ?=
SOURCE_DIR = src
CONFIG_HEADER = include/cryptofuzz/config.h
REPOSITORY_GENERATOR = tools/gen_repository.py
REPOSITORY_HEADERS = repository_tbl.h repository_map.h
OBJECT_FILES = \
bignum_fuzzer_importer.o botan_importer.o builtin_tests_importer.o components.o crypto.o datasource.o driver.o \
ecc_diff_fuzzer_exporter.o ecc_diff_fuzzer_importer.o entry.o executor.o expmod.o mutator.o mutatorpool.o numbers.o \
openssl_importer.o operation.o options.o repository.o tests.o util.o wycheproof.o z3.o

$(REPOSITORY_HEADERS) &: $(REPOSITORY_GENERATOR)
	./$(REPOSITORY_GENERATOR)

%.o : $(SOURCE_DIR)/%.cpp $(REPOSITORY_HEADERS) $(CONFIG_HEADER)
	$(CXX) $(CXXFLAGS) $< -c -o $@
executor.o : $(SOURCE_DIR)/executor.cpp $(CONFIG_HEADER)
	$(CXX) $(CXXFLAGS) $< -c -o $@
entry.o : $(SOURCE_DIR)/entry.cpp $(SOURCE_DIR)/extra_options.h repository_tbl.h
	$(CXX) $(CXXFLAGS) $< -c -o $@
components.o : $(SOURCE_DIR)/components.cpp $(CONFIG_HEADER)
	$(CXX) $(CXXFLAGS) $< -c -o $@
mutator.o : $(SOURCE_DIR)/mutator.cpp $(CONFIG_HEADER) $(SOURCE_DIR)/expmod.h
	$(CXX) $(CXXFLAGS) $< -c -o $@
z3.o : $(SOURCE_DIR)/z3.cpp $(CONFIG_HEADER) $(SOURCE_DIR)/_z3.h
	$(CXX) $(CXXFLAGS) $< -c -o $@
numbers.o : $(SOURCE_DIR)/numbers.cpp
	$(CXX) $(CXXFLAGS) -O0 $< -c -o $@

third_party/cpu_features/build/libcpu_features.a :
	cmake -S third_party/cpu_features -B third_party/cpu_features/build -DBUILD_TESTING=OFF
	cmake --build third_party/cpu_features/build --parallel $(BUILD_JOBS)

cryptofuzz : $(OBJECT_FILES) third_party/cpu_features/build/libcpu_features.a $(MODULE_LIBRARIES)
	test $(LIBFUZZER_LINK)
	$(CXX) $(CXXFLAGS) $(OBJECT_FILES) $(MODULE_LIBRARIES) $(LIBFUZZER_LINK) third_party/cpu_features/build/libcpu_features.a $(LINK_FLAGS) -o cryptofuzz

generate_dict: $(SOURCE_DIR)/generate_dict.cpp repository_map.h
	$(CXX) $(CXXFLAGS) $< -o $@

generate_corpus: $(SOURCE_DIR)/generate_corpus.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -rf $(OBJECT_FILES) $(REPOSITORY_HEADERS) cryptofuzz generate_dict generate_corpus

test-noble: $(REPOSITORY_HEADERS)
	set -e; for module in noble-ciphers noble-curves noble-ed25519 noble-hashes noble-post-quantum noble-secp256k1; do \
		$(MAKE) -C modules/$$module ids.js; \
		npm --prefix modules/$$module ci; \
		npm --prefix modules/$$module test; \
	done
