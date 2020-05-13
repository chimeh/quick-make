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

# trying the latter
build:
	$(MAKE) -C $(SDK)/box/native_box
	@ls --color $(SDK)/build/*/out



.PHONY: build
