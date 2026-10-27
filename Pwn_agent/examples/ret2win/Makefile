CC ?= gcc
CFLAGS ?= -O0 -g -fomit-frame-pointer -fno-stack-protector -no-pie -fno-builtin

.PHONY: all clean

all: chall

chall: chall.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f chall

