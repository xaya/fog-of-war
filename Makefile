# One library, one test binary. No dependencies beyond a C++17 compiler.
CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -fno-exceptions -fno-rtti
INC      := -Iinclude -Isrc

.PHONY: all test verify clean paper

all: test

build/test_fow: src/fow.cpp src/sha256.cpp tests/test_fow.cpp include/fow.hpp src/sha256.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(INC) -o $@ src/fow.cpp src/sha256.cpp tests/test_fow.cpp

# The C++ tests: RFC 7748 vectors, the subgroup identity, the protocol end to end,
# and the historical Dungeon Channel fixture.
test: build/test_fow
	@./build/test_fow

# The independent implementation: a from-scratch BigInt version written from the
# paper's formulas and its stated encoding conventions, checked against the same
# pinned vectors as the C++. Needs node only.
verify:
	@node tests/verify-math.mjs

paper:
	@cd paper && tectonic blinded-sighting-test.tex

clean:
	rm -rf build
