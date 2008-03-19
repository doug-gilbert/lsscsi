SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

CC = gcc
LD = gcc

EXECS = lsscsi

MAN_PGS = lsscsi.8
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS = -g -O2 -Wall -D_REENTRANT $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -D_REENTRANT -DSG_KERNEL_INCLUDES $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -pedantic -D_REENTRANT $(LARGE_FILE_FLAGS)

LDFLAGS =

all: $(EXECS)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core .depend

lsscsi: lsscsi.o
	$(LD) -o $@ $(LDFLAGS) $^

install: $(EXECS) $(COMMON)
	install -d $(INSTDIR)
	for name in $^; \
	 do install -s -o root -g root -m 755 $$name $(INSTDIR); \
	done
	for mp in $(MAN_PGS); \
	 do install -o root -g root -m 644 $$mp $(MANDIR)/$(MAN_PREF); \
	 gzip -9f $(MANDIR)/$(MAN_PREF)/$$mp; \
	done

uninstall:
	dists="$(EXECS)"; \
	for name in $$dists; do \
	 rm -f $(INSTDIR)/$$name; \
	done
	for mp in $(MAN_PGS); do \
	 rm -f $(MANDIR)/$(MAN_PREF)/$$mp.gz; \
	done

ifeq (.depend,$(wildcard .depend))
include .depend
endif
