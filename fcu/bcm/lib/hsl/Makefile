
#
# Makefile for SOC SAL support (Linux Kernel)
#
LOCALDIR = lib/hsl

include ${SDK}/mk/Make.config
ADD_LSRCS = $(wildcard common/*.c )
LSRCS += $(ADD_LSRCS)

CFLAGS += -D"DEBUG_HASH=43" -D"DEBUG_HASH2=50"
CFLAGS += -I${SDK}/$(LOCALDIR)/common
CFLAGS += -I${SDK}/$(LOCALDIR)
CFLAGS += -I${SDK}/lib/unixlib/netl
lib = libhsl
include ${SDK}/mk/Make.kernlib

include ${SDK}/mk/Make.depend
