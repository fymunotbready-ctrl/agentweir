CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS = -pthread
ifeq ($(shell uname),Linux)
LDFLAGS += -pie -Wl,-z,relro,-z,now
endif

# make STATIC=1 links the C++ runtime statically (used for the Docker image and release builds, Linux only).
ifeq ($(shell uname),Linux)
ifdef STATIC
LDFLAGS += -static-libstdc++ -static-libgcc
endif
endif

agentweir: src/main.cpp src/*.hpp
	$(CXX) $(CXXFLAGS) src/main.cpp -o agentweir $(LDFLAGS)

# Build with memory-error and undefined-behaviour detectors (used by the tests).
asan: src/main.cpp src/*.hpp
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer \
	  src/main.cpp -o agentweir-asan -pthread

test: asan
	ASAN_OPTIONS=detect_leaks=0 python3 tests/test_agentweir.py ./agentweir-asan

clean:
	rm -f agentweir agentweir-asan
