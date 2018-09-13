O=1
ifdef O
	CFLAGS=-Wall -O3 -c
	LDFLAGS=-O3
else
	CFLAGS=-Wall -g -pg -c
	LDFLAGS=-g -pg
endif

OBJS = hdcp_cipher.o hdcp.o
HEADERS = bitslice.h bitslice-autogen.h

hdcp: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

hdcp_cipher.o: hdcp_cipher.c $(HEADERS)
	$(CC) $(CFLAGS) hdcp_cipher.c

hdcp.o: hdcp.c $(HEADERS)
	$(CC) $(CFLAGS) hdcp.c

bitslice-autogen.h: bitslice-gen
	./bitslice-gen > $@

bitslice-gen: bitslice-gen.c
	$(CC) -Wall $< -o $@

clean:
	rm -f *.o *~ hdcp bitslice-gen bitslice-autogen.h

dist: hdcp.c hdcp_cipher.c hdcp_cipher.h bitslice.h bitslice-gen.c Makefile README
	mkdir hdcp-0.5
	cp $^ hdcp-0.5/
	tar cvzf hdcp-0.5.tgz     hdcp-0.5
	tar cvjf hdcp-0.5.tar.bz2 hdcp-0.5
	tar cvJf hdcp-0.5.txz     hdcp-0.5
	rm -rf hdcp-0.5