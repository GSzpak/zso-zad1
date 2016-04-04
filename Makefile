TARGET: raise.out test.out

MMAP_MIN_ADDR_DEC = $(shell sysctl -n vm.mmap_min_addr)
MMAP_MIN_ADDR_HEX = $(shell printf "%x" $(MMAP_MIN_ADDR_DEC))
CC = gcc
CFLAGS = -Wall -m32 -D_GNU_SOURCE -c
LDFLAGS = -Wall -m32 -D_GNU_SOURCE -static \
	-Wl,--section-start=.rel.plt=0x00148138 \
	-Wl,--section-start=.init=0x001481a8 \
	-Wl,--section-start=.plt=0x001481d0 \
	-Wl,--section-start=.text=0x001482b0
	#-Ttext=0x00100000 #-Wl,--section-start=.data=0x00600000


raise.out: raise.o libc.a
	$(CC) $(LDFLAGS) $^ -o $@

raise.o: raise.c
	$(CC) $(CFLAGS) $^

test.out: test.c
	gcc -Wall -m32 -D_GNU_SOURCE $^ -o $@

clean:
	rm -f *.out *.o *~ *.bak
