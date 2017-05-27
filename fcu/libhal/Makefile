CFLAGS+= -I.
CFLAGS+= -I../quagga-lib
CFLAGS+= -g




LDFLAGS_ +=  -static

SLIB = libhal.a

ifeq ($(TGTDIR),)
include ../Makefile.inc
else 
include $(TGTDIR)/Makefile.inc
endif

