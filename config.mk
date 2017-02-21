PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include
MANDIR=$(PREFIX)/share/man

CFLAGS+=-std=c99 -g -O2 -fstack-protector-strong -Iinclude
CFLAGS+=-Wall -Wextra -Wwrite-strings -Wno-switch -Wno-extended-offsetof -pedantic
CPPFLAGS+=-D_DEFAULT_SOURCE -D_GNU_SOURCE -D_FORTIFY_SOURCE=2

CC=cc
