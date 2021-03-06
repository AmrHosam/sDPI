#
# Simple non-autotools dependent makefile
#
# ./autogen.sh
# cd src/lib
# make Makefile
#


#
# Installation directories
#
prefix     = /usr/local
libdir     = ${prefix}/lib
includedir = ${prefix}/include/ndpi
CC         = gcc
CFLAGS     += -fPIC -DPIC -I../include -Ithird_party/include -DNDPI_LIB_COMPILATION -O2 -g -Wall 
RANLIB     = ranlib

OBJECTS   = $(patsubst protocols/%.c, protocols/%.o, $(wildcard protocols/*.c)) $(patsubst third_party/src/%.c, third_party/src/%.o, $(wildcard third_party/src/*.c)) $(patsubst ./%.c, ./%.o, $(wildcard ./*.c))
HEADERS   = $(wildcard ../include/*.h)
NDPI_VERSION_MAJOR   = 3
NDPI_LIB_STATIC      = libndpi.a
NDPI_LIB_SHARED_BASE = libndpi.so
NDPI_LIB_SHARED      = $(NDPI_LIB_SHARED_BASE).3.1.0
NDPI_LIBS            = $(NDPI_LIB_STATIC) $(NDPI_LIB_SHARED)

ifneq ($(OS),Windows_NT)
OS := $(shell uname)
endif

ifeq ($(OS),Darwin)
CC=clang
SONAME_FLAG=
else
SONAME_FLAG=-Wl,-soname,$(NDPI_LIB_SHARED_BASE).$(NDPI_VERSION_MAJOR)
endif

all:$(NDPI_LIBS)

ndpi_main.c: ndpi_content_match.c.inc

$(NDPI_LIB_STATIC): $(OBJECTS)
	   ar rc $@ $(OBJECTS)
	   $(RANLIB) $@	       

$(NDPI_LIB_SHARED): $(OBJECTS)
	$(CC) -shared -fPIC $(SONAME_FLAG) -o $@ $(OBJECTS)
	ln -fs $(NDPI_LIB_SHARED) $(NDPI_LIB_SHARED_BASE)
	ln -fs $(NDPI_LIB_SHARED) $(NDPI_LIB_SHARED_BASE).$(NDPI_VERSION_MAJOR)

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	/bin/rm -f $(NDPI_LIB_STATIC) $(OBJECTS) *.o *.so *.lo $(NDPI_LIB_SHARED)

distclean: clean
	/bin/rm -f Makefile

cppcheck:
	cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force -I ../include *.c protocols/*.c

install: $(NDPI_LIBS)
	mkdir -p $(DESTDIR)$(libdir)
	cp $(NDPI_LIBS) $(DESTDIR)$(libdir)/
	cp -P $(NDPI_LIB_SHARED_BASE) $(DESTDIR)$(libdir)/
	cp -P $(NDPI_LIB_SHARED_BASE).$(NDPI_VERSION_MAJOR) $(DESTDIR)$(libdir)/
	mkdir -p $(DESTDIR)$(includedir)
	cp ../include/*.h $(DESTDIR)$(includedir)
