
INSTALL_DIR ?= out/

CC ?= $(CROSS_COMPILE)gcc

CFLAGS += -g -Os
CFLAGS += -std=gnu89
CFLAGS += -Wall
CFLAGS += -Wp,-MT,$@,-MD,$(@D)/.$(@F).d
CFLAGS += -D_GNU_SOURCE

CFLAGS += -DDEBUG

sources-y := igmp.c rawigmp.c mld.c rawmld.c helpers.c mcquery.c
objects-y := $(patsubst %.c,%.o,$(sources-y))
depends-y := $(wildcard .*.d)

all: mcquery Makefile

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS-$<) -c -o $@ $<

mcquery: $(objects-y)
	$(CC) $(LDFLAGS) -o $@ $^ ${LDLIBS}

clean:
	rm -f mcquery *.o

-include $(depends-y)
