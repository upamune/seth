CLANG_FORMAT=clang-format
PROGRAM=SEth
OBJS=param.o sock.o ether.o arp.o ip.o icmp.o cmd.o main.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
LDFLAGS=-lpthread

.PHONY: fmt
fmt:
	find . -maxdepth 2 -iname '*.h' -o -iname '*.c' | xargs $(CLANG_FORMAT) -style=LLVM -i

$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS) $(LDFLAGS)
