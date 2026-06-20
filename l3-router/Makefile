CC     ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2 -Iinclude
CORE    = src/ip.c src/eth.c src/arp.c src/iptrie.c src/router.c
OBJ     = $(CORE:.c=.o) src/sim.o src/tap.o

all: router

router: $(OBJ) src/main.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(CORE:.c=.o) tests/test_l3.o
	$(CC) $(CFLAGS) -o run_tests $(CORE:.c=.o) tests/test_l3.o
	./run_tests

clean:
	rm -f src/*.o tests/*.o router run_tests

.PHONY: all test clean
