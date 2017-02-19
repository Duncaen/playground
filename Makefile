.error : This Makefile needs GNU make
include config.mk

PROGS = pledge # newns
LIBS = libpledge # libnewns
ALL = $(LIBS:=.a) $(LIBS:=.so) $(PROGS)

all: options $(ALL)

$(PROGS) : % : %.o
$(LIBS:=.a) : %.a : %.o
$(LIBS:=.so) : %.so : %.o

libpledge.o : include/pledge_syscalls.h include/seccomp_bpf_utils.h
libpledge.o pledge.o : include/pledge.h

pledge: libpledge.a
# newns: libnewns.a

pledge:
	$(CC) $^ -o $@ $(LDFLAGS)

# newns:
# 	$(CC) $^ -o $@ $(LDFLAGS)

%.a:
	ar rc $@ $^

%.so:

options:
	@echo "CFLAGS  = ${CFLAGS}"
	@echo "LDFLAGS = ${LDFLAGS}"
	@echo "CC      = ${CC}"

tests:
	make -C tests/pledge

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

.PHONY: all options tests clean install
