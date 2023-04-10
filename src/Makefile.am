bin_PROGRAMS = lsscsi

# C++/clang testing
## CC = gcc-8
## CC = g++
## CC = clang
## CC = clang++

# INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/include/scsi

## AM_CFLAGS = -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W

# -std=<s> can be c99, c11, gnu11, etc.
AM_CPPFLAGS = -iquote ${top_srcdir}/src -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
### AM_CFLAGS = -Wall -W
AM_CFLAGS = -Wall -W -Wextra -Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wnull-dereference -Wshadow -Wjump-misses-init
# AM_CFLAGS = -Wall -W -pedantic -std=c99
# AM_CFLAGS = -Wall -W -pedantic -std=c11
# AM_CFLAGS = -Wall -W -pedantic -std=c11 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++11
# AM_CFLAGS = -Wall -W -pedantic -std=gnu++1z
# AM_CFLAGS = -Wall -W -pedantic -std=c++20
# AM_CFLAGS = -Wall -W -pedantic -std=c++20 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++23


lsscsi_SOURCES =	lsscsi.c sg_json_builder.c sg_pr2serr.c

distclean-local:
	rm -rf .deps
