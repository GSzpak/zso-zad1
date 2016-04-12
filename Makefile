TARGET: raise test

MMAP_MIN_ADDR_DEC = $(shell sysctl -n vm.mmap_min_addr)
MMAP_MIN_ADDR_HEX = $(shell printf "%x" $(MMAP_MIN_ADDR_DEC))
CC = gcc
CFLAGS = -Wall -pedantic -std=c99 -m32 -D_GNU_SOURCE -g -c
LDFLAGS = -Wall -pedantic -std=c99 -m32 -D_GNU_SOURCE -static \
	-Wl,--section-start=.note.gnu.build-id=0x0065536 \
	-Wl,--section-start=.note.ABI-tag=0x001480f6 \
	-Wl,--section-start=.rel.plt=0x00148138 \
	-Wl,--section-start=.init=0x001481a8 \
	-Wl,--section-start=.plt=0x001481d0 \
	-Wl,--section-start=.text=0x001482b0
	#-Wl,--section-start=.note.gnu.build-id=0x00010400 \
    #-Wl,--section-start=.note.ABI-tag=0x00020400 \
    #-Wl,--section-start=.init=0x00100400 \
    #-Wl,--section-start=.text=0x00200400


raise: raise.o
	$(CC) $(LDFLAGS) $^ -o $@

raise.o: raise.c
	$(CC) $(CFLAGS) $^

test: test.c
	gcc -Wall -m32 -g -D_GNU_SOURCE $^ -o $@

clean:
	rm -f raise test *.o *~ *.bak
