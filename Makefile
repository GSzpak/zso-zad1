TARGET: raise


CC = gcc
CFLAGS = -Wall -std=c99 -m32 -D_GNU_SOURCE -c
LDFLAGS = -Wall -std=c99 -m32 -D_GNU_SOURCE -static \
	-Wl,--section-start=.note.gnu.build-id=0x01000400 \
	-Wl,--section-start=.note.ABI-tag=0x01100400 \
	-Wl,--section-start=.init=0x01200400 \
	-Wl,--section-start=.text=0x02000400


raise: raise.o raise_utils.o
	$(CC) $(LDFLAGS) $^ -o $@

raise.o: raise.c
	$(CC) $(CFLAGS) $^

raise_utils.o: raise_utils.c
	$(CC) $(CFLAGS) $^

clean:
	rm -f raise *.o *~ *.bak
