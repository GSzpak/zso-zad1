TARGET: raise


CC = gcc
CFLAGS = -Wall -std=c99 -m32 -D_GNU_SOURCE -c
LDFLAGS = -Wall -std=c99 -m32 -D_GNU_SOURCE -static \
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


raise: raise.o raise_utils.o
	$(CC) $(LDFLAGS) $^ -o $@

raise.o: raise.c
	$(CC) $(CFLAGS) $^

raise_utils.o: raise_utils.c
	$(CC) $(CFLAGS) $^

clean:
	rm -f raise *.o *~ *.bak
