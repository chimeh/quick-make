
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

override-target=unix-user

ifeq ($(LINUX_MAKE_SHARED_LIB),1)
libext = so.$(SHAREDLIBVER)
else
libext = a
endif

ifeq (,$(platform))
$(error Internal error: platform variable is not set)
endif

include $(SDK)/mk/Make.config
LOCALDIR=app/linuxuser/diag
include $(SDK)/mk/Make.depend


ifeq ($(DEST_DIR),)
DEST_DIR=${BLDDIR}
endif

NETSERVE := $(DEST_DIR)/netserve





# Allow override of default make target
ifeq (,$(DEFAULT_MAKE_TARGET))
.DEFAULT_GOAL := all
else
.DEFAULT_GOAL := $(DEFAULT_MAKE_TARGET)
endif




# Build all targets
all: $(BLDDIR)/.tree $(all_targets)









BCM_LIBS =  $(DRV_LIBS)  $(COND_LIB_ETH_DRV)
BCM_LIBS_BLD = $(addprefix $(BLDDIR)/,$(BCM_LIBS))




$(NETSERVE): $(BLDDIR)/netserve.o
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $(BLDDIR)/netserve.o $(LDFLAGS)
	$(OBJCOPY) --strip-debug $@


# Build Version
$(BLDDIR)/version.c: $(BCM_LIBS_BLD)
	$(PERL) $(SDK)/tools/version.pl > $@
$(BLDDIR)/version.o: $(BLDDIR)/version.c
	$(CC) $(CFLAGS) -c $< -o $@



distclean:: clean

.PHONY: variable



# Make.config defines remaining phony targets
.PHONY: build kernel_modules user_libs DELIVER mod bcm user
