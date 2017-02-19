.error : This Makefile needs GNU make
CFLAGS+=-std=c99 -g -O2 -fstack-protector-strong -Iinclude
CFLAGS+=-Wall -Wextra -Wwrite-strings -Wno-switch -Wno-extended-offsetof -pedantic
CPPFLAGS+=-D_DEFAULT_SOURCE -D_FORTIFY_SOURCE=2

DESTDIR=
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include
MANDIR=$(PREFIX)/share/man

PROGS = pledge # newns
LIBS = libpledge # libnewns
ALL = $(LIBS:=.a) $(LIBS:=.so) $(PROGS)

all: $(ALL)

$(PROGS) : % : %.o
$(LIBS:=.a) : %.a : %.o
$(LIBS:=.so) : %.so : %.o

libpledge.o : include/pledge_syscalls.h
libpledge.o pledge.o : include/pledge.h

pledge: libpledge.a
# newns: libnewns.a

pledge:
	$(CC) $^ -o $@ $(LDFLAGS)

ns:
	$(CC) $^ -o $@ $(LDFLAGS)

%.a:
	ar rc $@ $^

%.so:

clean:
	-rm -f $(ALL) *.o

install: all
	mkdir -p $(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(LIBDIR) \
		$(DESTDIR)$(INCDIR)
	install -m0644 libpledge.a libpledge.so $(DESTDIR)$(LIBDIR)
	install -m0644 include/pledge.h $(DESTDIR)$(INCDIR)
	install -m0755 pledge $(DESTDIR)$(BINDIR)
	# install -m0755 newns $(DESTDIR)$(BINDIR)
	# install -m0644 libnewns.a libnewns.so $(DESTDIR)$(LIBDIR)
	# install -m0644 newns.h $(DESTDIR)$(INCDIR)

.PHONY: all clean install
