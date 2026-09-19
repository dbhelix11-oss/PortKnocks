CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
INCLUDES := -Iinclude
LIBS := -lcrypto -lpcap

SRC := src/derive.cpp src/hmac_verify.cpp src/session.cpp src/firewall.cpp src/sniffer.cpp src/config.cpp src/log.cpp src/proc.cpp src/commands.cpp
OBJ := $(SRC:.cpp=.o)

.PHONY: all clean test

all: knockd

knockd: $(OBJ) src/main.o
	$(CXX) $(CXXFLAGS) $(OBJ) src/main.o $(LIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

test_derive: src/derive.cpp src/hmac_verify.cpp tests/test_derive.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -Itests $^ -lcrypto -o $@

test_session: src/derive.cpp src/hmac_verify.cpp src/session.cpp src/log.cpp tests/test_session.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -Itests $^ -lcrypto -o $@

test_config: src/config.cpp tests/test_config.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -Itests $^ -o $@

test: test_derive test_session test_config
	./test_derive
	./test_session
	./test_config

clean:
	rm -f $(OBJ) src/main.o knockd test_derive test_session test_config
