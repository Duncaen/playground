.error : This Makefile needs GNU make
include ../../config.mk
CFLAGS+=-I../../include

SRCS=$(shell ls test_*.c)
TEST=${SRCS:.c=}

all: options tests clean

test_filter_conditions.o: ../../include/pledge.h

$(TEST) : % : %.o

$(TEST):
	$(CC) $^ -o $@ $(LDFLAGS)

options:
	@echo "CFLAGS  = ${CFLAGS}"
	@echo "LDFLAGS = ${LDFLAGS}"
	@echo "CC      = ${CC}"

tests: $(TEST)
	@for t in $<; do ./$$t || exit $$?; done

clean:
	-rm -f $(TEST) *.o

.PHONY: all options tests clean
