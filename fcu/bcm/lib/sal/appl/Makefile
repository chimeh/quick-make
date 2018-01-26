###################################################################
#automatic detection SDK and LOCALDIR
CUR_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
TRYSDK := $(shell if [ -n "$$SDK" ] ; then\
        echo $$SDK;\
        else\
        cd $(CUR_DIR); while /usr/bin/test ! -e RELEASE ; do \
        dir=`cd ../;pwd`;                       \
        if [ "$$dir" = "/" ] ; then             \
           echo Cannot find SDK in $(firstword $(MAKEFILE_LIST)) 1>&2; \
           exit 1;                              \
        fi ;                                    \
        cd $$dir;                               \
        done ;                                  \
        pwd;                                    \
        fi)
SDK ?= $(realpath ${TRYSDK})

ifeq ($(SDK),)
$(error Please run this in a tree)
endif
LOCALDIR = $(patsubst %/,%,$(subst $(realpath $(SDK))/,,$(CUR_DIR)))
####################################################################

include ${SDK}/mk/Make.config

ifeq (linuxkern,$(targetos))
endif

 
subdirs = editline
 
include ${SDK}/mk/Make.subdirs

ifeq ($(targetos),linuxkern)
    LSRC += $(wildcard linuxkern)
endif
ifeq ($(targetos),linuxkern)
    LSRC += $(wildcard linuxuser)
    CFLAGS += -DNO_FILEIO
endif
ifeq ($(targetos),vxworks)
    LSRC += $(wildcard vxworks)
endif

CFLAGS += -I$(realpath $(SDK)/$(LOCALDIR)/../h)

lib = libsal_appl

include ${SDK}/mk/Make.lib

include ${SDK}/mk/Make.depend



