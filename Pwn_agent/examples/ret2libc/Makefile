CC ?= gcc
CFLAGS ?= -O0 -fno-stack-protector -no-pie -Wl,-z,noexecstack

.PHONY: all clean

all: chall

chall: chall.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f chall
