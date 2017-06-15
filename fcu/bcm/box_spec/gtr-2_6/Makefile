

#
# This make job requires the following environment variables to be set:
#
# SDK                - path to StrataXGS SDK root directory
#
# Optionally the following environment variables can be set to
# override the default build server configuration:
#
# PPC_TOOLS_DIR      - path to build tools (if not in PATH already)
# PPC_CROSS_COMPILE  - cross compile tools prefix
# LINUX_INCLUDE      - path to Linux kernel include directory
#

SDK :=$(shell if [ -n "$$SDK" ] ; then\
	echo $$SDK;\
	else\
	cd $(dir $(lastword $(MAKEFILE_LIST))); while /usr/bin/test ! -e RELEASE ; do \
	dir=`cd ../;pwd`;			\
	if [ "$$dir" = "/" ] ; then		\
	   echo Cannot find SDK in $(lastword $(MAKEFILE_LIST)) 1>&2;		\
	   exit 1;				\
	fi ;					\
	cd $$dir;				\
	done ;					\
	pwd;					\
	fi)

ifeq ($(SDK),)					
$(error Please run this in a tree)		
endif 				

export SDK


override kernel_version=2_6
platform=gtr-2_6
LINUX_MAKE_USER=1
export LINKER_RELAX=1

XMC ?= /projects/ntsw-tools/toolchains/xlp316/sdk-base
TOOLS_DIR = $(XMC)/toolchains_bin/mipscross/linux/bin


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

ifeq (,$(kernel_version))
kernel_version=2_4
endif

ifndef LINUX_MAKE_SHARED_LIB
LINUX_MAKE_SHARED_LIB=0
endif

ifeq (,$(SHAREDLIBVER))
SHAREDLIBVER=1
endif

ifndef LINUX_MAKE_DIR
ifdef LINUX_MAKE_USER
LINUX_MAKE_DIR := $(SDK)/app/linuxuser/common
else
LINUX_MAKE_DIR := $(SDK)/app/linuxkern/common
endif
endif

ifdef LINUX_MAKE_USER
  CMD = $(LINUX_MAKE_FLAGS) -C $(LINUX_MAKE_DIR) \
        platform=$(platform) bldroot_suffix=/$(platform) kernel_version=$(kernel_version) \
        LINUX_MAKE_SHARED_LIB=$(LINUX_MAKE_SHARED_LIB) SHAREDLIBVER=$(SHAREDLIBVER)
else
  export LINUX_MAKE_KERNEL := 1
  CMD = $(LINUX_MAKE_FLAGS) -C $(LINUX_MAKE_DIR) \
        platform=$(platform) kernel_version=$(kernel_version)
endif

ifneq (,$(MIPS_TOOLS_DIR))
  CMD += MIPS_TOOLS_DIR=$(MIPS_TOOLS_DIR)
endif

ifneq (,$(MIPS_CROSS_COMPILE))
  CMD += MIPS_CROSS_COMPILE=$(MIPS_CROSS_COMPILE)
endif

ifneq (,$(LINUX_INCLUDE))
  CMD += LINUX_INCLUDE=$(LINUX_INCLUDE)
endif

DEBUG_MAKEFILE_TARGET := debug_makefile_allvalue_notexpand
DEBUG_MAKEFILE_TARGET += debug_makefile_allvalue_expand
DEBUG_MAKEFILE_TARGET += debug_makefile_varlist
DEBUG_MAKEFILE_TARGET += debug_makefile_onevar
# gmake does not understand $(CMD) to be a submake
# options are to +$(CMD) or $(MAKE) $(CMD)
# trying the latter
build:
	$(MAKE) $(CMD)

DELIVER clean C_COMPILER CXX_COMPILER variable mod bcm user $(DEBUG_MAKEFILE_TARGET):
	$(MAKE) $(CMD) $@

distclean clean_d: clean

.PHONY: build clean distclean clean_d DELIVER variable mod bcm user $(DEBUG_MAKEFILE_TARGET)



