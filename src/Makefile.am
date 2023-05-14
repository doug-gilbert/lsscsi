bin_PROGRAMS = lsscsi

# C++/clang testing
## CC = gcc-8
## CC = g++
## CC = clang
## CC = clang++

if DEBUG
# This is active if --enable-debug given to ./configure
# removed -Wduplicated-branches because needs gcc-8
DBG_CFLAGS = -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument -Wduplicated-branches
# DBG_CFLAGS = -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument -Wduplicated-branches -Wjump-misses-init
DBG_CPPFLAGS = -DDEBUG
else
DBG_CFLAGS =
DBG_CPPFLAGS =
endif

# INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/include/scsi

## AM_CFLAGS = -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W

# -std=<s> can be c99, c11, gnu11, etc.
AM_CPPFLAGS = -iquote ${top_srcdir}/src -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(DBG_CPPFLAGS)
AM_CFLAGS = -Wall -W $(DBG_CFLAGS)
# AM_CFLAGS = -Wall -W -Wextra -Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wnull-dereference -Wshadow
# AM_CFLAGS = -Wall -W $(DBG_CFLAGS) -fanalyzer
# AM_CFLAGS = -Wall -W -pedantic -std=c99
# AM_CFLAGS = -Wall -W -pedantic -std=c11
# AM_CFLAGS = -Wall -W -pedantic -std=c11 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++11
# AM_CFLAGS = -Wall -W -pedantic -std=gnu++1z
# AM_CFLAGS = -Wall -W -pedantic -std=c++20
# AM_CFLAGS = -Wall -W -pedantic -std=c++20 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++23


lsscsi_SOURCES =	lsscsi.c \
			sg_json_builder.h \
			sg_json_builder.c \
			sg_pr2serr.h \
			sg_pr2serr.c \
			sg_json.h \
			sg_json.c \
			sg_unaligned.h

distclean-local:
	rm -rf .deps
