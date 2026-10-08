CC      ?= gcc
OPT     ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wextra $(OPT) -DPBC_SUPPORT
LDLIBS  += -lm -lgmp -lnettle -lhogweed -lpbc

SRCS := $(wildcard lib-*.c)

test-ibsr: test-utility.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) test-utility.c $(SRCS) -o $@ $(LDLIBS)

clean:
	rm -f test-ibsr

.PHONY: clean
