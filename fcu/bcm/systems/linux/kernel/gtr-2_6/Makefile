

#
# This make job requires the following environment variables to be set:
#
# SDK                - path to StrataXGS SDK root directory
#
# Optionally the following environment variables can be set to
# override the default build server configuration:
#
# MIPS_TOOLS_DIR     - path to build tools (if not in PATH already)
# MIPS_CROSS_COMPILE - cross compile tools prefix
# LINUX_INCLUDE      - path to Linux kernel include directory
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
override kernel_version=2_6
export SDK

platform=gtr-${kernel_version}
LDFLAGS = ""
include ${SDK}/make/Make.linux

