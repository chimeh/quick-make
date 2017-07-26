
#
LOCALDIR = lib/unixlib/quagga

include ${SDK}/mk/Make.config
CFLAGS+=-I${SDK}/$(LOCALDIR)
CFLAGS+= -DHAVE_CONFIG_H -DSYSCONFDIR=\"/usr/local/etc/\"

lib = libquagga
include ${SDK}/mk/Make.lib

include ${SDK}/mk/Make.depend
