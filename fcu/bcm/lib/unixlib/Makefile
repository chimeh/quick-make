
#
# Makefile for SOC SAL support
#
LOCALDIR = lib/unixlib

include ${SDK}/mk/Make.config

ifeq (linuxuser,$(targetbase))
subdirs=netl quagga
endif

include ${SDK}/mk/Make.subdirs

include ${SDK}/mk/Make.depend
