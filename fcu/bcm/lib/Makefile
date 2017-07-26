


CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TRYSDK := $(shell if [ -n "$$SDK" ] ; then\
        echo $$SDK;\
        else\
        cd $(CUR_DIR); while /usr/bin/test ! -e RELEASE ; do \
        dir=`cd ../;pwd`;                       \
        if [ "$$dir" = "/" ] ; then             \
           echo Cannot find SDK in $(lastword $(MAKEFILE_LIST)) 1>&2;           \
           exit 1;                              \
        fi ;                                    \
        cd $$dir;                               \
        done ;                                  \
        pwd;                                    \
        fi)
SDK := ${TRYSDK}
$(warning  "SDK=${SDK}")
ifeq ($(SDK),)
$(error Please run this in a tree)
endif

export SDK

include ${SDK}/mk/Make.config

export TARGET
export BLDDIR
export LIBDIR


subdirs = customer sal unixlib

ifeq ($(targetbase),linuxkern)
subdirs += hsl
endif

override MAKEFLAGS += TARGET=$(TARGET)

include ${SDK}/mk/Make.subdirs


