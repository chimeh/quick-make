#
CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TRYSDK := $(shell if [ -n "$$SDK" ] ; then\
	echo $$SDK;\
	else\
	cd $(CUR_DIR); while /usr/bin/test ! -e RELEASE ; do \
	dir=`cd ../;pwd`;			\
	if [ "$$dir" = "/" ] ; then		\
	   echo Cannot find SDK in $(lastword $(MAKEFILE_LIST)) 1>&2;		\
	   exit 1;				\
	fi ;					\
	cd $$dir;				\
	done ;					\
	pwd;					\
	fi)
SDK := ${TRYSDK}
$(warning  "SDK=${SDK}")
ifeq ($(SDK),)					
$(error Please run this in a tree)		
endif

export SDK



# 
# Common make targets for Linux user and kernel builds included by top
# level Linux makefiles
#
# Variables referenced:
#
# LINUX_MAKE_FLAGS
#   Additional flags passed to Make
#
# LINUX_MAKE_USER
#   Defined: user build
#   Undefined: kernel build
#
# LINUX_MAKE_DIR
#   Common makefile location, if it is not ../common
#
#

export DEST_DIR_SUFFIX :=$(subst $(realpath $(SDK))/app,,$(realpath $(CURDIR)/$(dir ($(firstword $(MAKEFILE_LIST))))))

LINUX_MAKE_FLAGS :=
LINUX_MAKE_DIR := $(SDK)/app/linuxkern/bcm-core/
platform=gtr-2_6
bldroot_suffix := xx
override kernel_version=2_6
LINUX_MAKE_SHARED_LIB=0
SHAREDLIBVER=1
LINUX_INCLUDE := /home/jimmy/inspur-sw-yh/trunk/mcb-f9-sdk/linux/include
KERNDIR :=/home/jimmy/inspur-sw-yh/trunk/mcb-f9-sdk/linux 
CROSS_COMPILE := mips64-nlm-linux-



CMD = $(LINUX_MAKE_FLAGS) \
        platform=$(platform) \
        bldroot_suffix=$(bldroot_suffix) \
        kernel_version=$(kernel_version) \
        LINUX_MAKE_SHARED_LIB=$(LINUX_MAKE_SHARED_LIB) \
        SHAREDLIBVER=$(SHAREDLIBVER) \
        LINUX_INCLUDE=$(LINUX_INCLUDE) \
        KERNDIR=$(KERNDIR) \
        CROSS_COMPILE=$(CROSS_COMPILE)



DEBUG_MAKEFILE_TARGET := debug_makefile_allvalue_notexpand
DEBUG_MAKEFILE_TARGET += debug_makefile_allvalue_expand
DEBUG_MAKEFILE_TARGET += debug_makefile_varlist
DEBUG_MAKEFILE_TARGET += debug_makefile_onevar
# gmake does not understand $(CMD) to be a submake
# options are to +$(CMD) or $(MAKE) $(CMD)
# trying the latter
build:
	$(MAKE) $(CMD) override-target=linuxkern.$(platform) -C $(SDK)/lib 
	$(MAKE) $(CMD) override-target=linuxkern.$(platform) -C $(SDK)/app/linuxkern/bcm-core
	$(MAKE) $(CMD)  -C $(SDK)/app/linuxuser/diag CFLAGS="-DBBB"
DELIVER clean C_COMPILER CXX_COMPILER  mod  user $(DEBUG_MAKEFILE_TARGET) DBG_MKEP DBG_MKNEP:
	$(MAKE) $(CMD) -C $(SDK)/lib $@

distclean clean_d: clean

.PHONY: build clean distclean clean_d DELIVER DBG_MKEP DBG_MKNEP  mod  user $(DEBUG_MAKEFILE_TARGET)



