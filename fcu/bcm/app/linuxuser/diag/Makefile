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

CFLAGS += -D"DEBUG_HASH=43" -D"DEBUG_HASH2=50"
CFLAGS += -I${SDK}/$(LOCALDIR)/common
CFLAGS += -I${SDK}/$(LOCALDIR)

LDFLAGS += -L$(LIBDIR)
exec = test_json
LD_O_FILES = $(BOBJS)
LD_A_FILES =
LD_L_LISTS += -lm
include ${SDK}/mk/Make.exec
include ${SDK}/mk/Make.depend

