CC=gcc
CXX=g++
CFLAGS=-g -I../src/include -g -O2 -I/usr/include/json-c
LIBNDPI=../src/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap -lpthread -lm  -ljson-c
OBJS=ndpiReader.o reader_util.o
PREFIX?=/usr/local

all: ndpiReader 

ndpiReader: $(OBJS) $(LIBNDPI)
	$(CXX) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	mkdir -p $(DESTDIR)$(PREFIX)/sbin/ndpi
	cp ndpiReader $(DESTDIR)$(PREFIX)/bin/
	cp protos.txt $(DESTDIR)$(PREFIX)/sbin/ndpi/ndpiProtos.txt
	cp mining_hosts.txt $(DESTDIR)$(PREFIX)/sbin/ndpi/ndpiCustomCategory.txt
	[ -f build/app/ndpiReader.dpdk ] && cp build/app/ndpiReader.dpdk $(DESTDIR)$(PREFIX)/bin/ || true
	[ -f ndpiReader.dpdk ] && cp ndpiReader.dpdk $(DESTDIR)$(PREFIX)/bin/ || true

dpdk:
	make -f Makefile.dpdk

check:
	 cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force -I../src/include *.c

clean:
	/bin/rm -f *.o ndpiReader ndpiReader.dpdk
	/bin/rm -f .*.dpdk.cmd .*.o.cmd *.dpdk.map .*.o.d
	/bin/rm -f _install _postbuild _postinstall _preinstall
	/bin/rm -rf build

distclean: clean
	/bin/rm -f Makefile.dpdk
	/bin/rm -f Makefile
