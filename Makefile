.error : This Makefile needs GNU make
CFLAGS+=-g -O2 -Wall -Wno-switch -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2

DESTDIR=
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include
MANDIR=$(PREFIX)/share/man

PROGS = pledge newns
LIBS = libpledge libnewns
ALL = $(LIBS:=.a) $(LIBS:=.so) $(PROGS)

all: $(ALL)

$(PROGS) : % : %.o
$(LIBS:=.a) : %.a : %.o
$(LIBS:=.so) : %.so : %.o

pledge: libpledge.a
newns: libnewns.a

pledge:
	$(CC) $^ -o $@ $(LDFLAGS)

ns:
	$(CC) $^ -o $@ $(LDFLAGS)

%.a:
	ar rc $@ $^

%.so:

clean: FRC
	-rm -f $(ALL) *.o

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(LIBDIR) \
		$(DESTDIR)$(INCDIR)
	install -m0644 libpledge.a libpledge.so $(DESTDIR)$(LIBDIR)
	install -m0644 pledge.h $(DESTDIR)$(INCDIR)
	install -m0755 pledge $(DESTDIR)$(BINDIR)

FRC:
