CLANG_FORMAT=clang-format
PROGRAM=SEth
OBJS=main.o param.o sock.o ether.o arp.o ip.o icmp.o cmd.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
LDFLAGS=-lpthread

.PHONY: fmt
fmt:
	find . -maxdepth 2 -iname '*.h' -o -iname '*.c' | xargs $(CLANG_FORMAT) -style=LLVM -i

$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
