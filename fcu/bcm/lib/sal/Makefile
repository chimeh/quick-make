
#
# Makefile for SOC SAL support
#
LOCALDIR = lib/sal

include ${SDK}/mk/Make.config

ifdef SAL_CORE_OVERRIDE
subdirs=${SAL_CORE_OVERRIDE}
else
subdirs=core
endif

# The sal_appl is not valid for all platforms
ifndef NO_SAL_APPL
subdirs += appl
endif

include ${SDK}/mk/Make.subdirs

include ${SDK}/mk/Make.depend
