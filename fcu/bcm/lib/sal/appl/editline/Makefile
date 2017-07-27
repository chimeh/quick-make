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

CFLAGS += -DANSI_ARROWS -DUNIQUE_HISTORY -DHIST_SIZE=64

ifeq (${targetbase},posix)
CFLAGS += -DSYS_UNIX -DHAVE_TCGETATTR -DUSE_DIRENT
endif

ifeq (${targetbase},unix)
CFLAGS += -DSYS_UNIX -DHAVE_TCGETATTR -DUSE_DIRENT
endif

ifneq (${targetbase},linux)
CFLAGS += -DHAVE_STDLIB
endif

lib = libsal_appl_editline
include ${SDK}/mk/Make.lib

include ${SDK}/mk/Make.depend
