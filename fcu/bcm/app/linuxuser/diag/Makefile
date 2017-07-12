
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

override-target=linuxu-gtr-2_6

ifeq ($(LINUX_MAKE_SHARED_LIB),1)
libext = so.$(SHAREDLIBVER)
else
libext = a
endif

ifeq (,$(platform))
#$(error Internal error: platform variable is not set)
endif

LOCALDIR=app/linuxuser/diag
include $(SDK)/mk/Make.config

CFLAGS += -I$(SDK)/$(LOCALDIR)
include $(SDK)/mk/Make.depend


THISAPP_LOCAL := test_json
THISAPP := $(BLDDIR)/$(THISAPP_LOCAL)

# Allow override of default make target
ifeq (,$(DEFAULT_MAKE_TARGET))
.DEFAULT_GOAL := all
else
.DEFAULT_GOAL := $(DEFAULT_MAKE_TARGET)
endif




# Build all targets
all: $(BLDDIR)/.tree $(THISAPP)




user_libs:
	$(MAKE) -C $(SDK)/lib/sal




$(BCM): $(BCM).dbg
	mkdir -p $(@D)
	$(OBJCOPY) --strip-debug $< $@

$(THISAPP): user_libs $(BOBJS) $(BLDDIR)/version.o 
	@rm -f $@	# Prevent core dump if currently running
	@echo Linking $@ # This is needed for error parsing
	$(CC) $(CFLAGS) -o $@  $(BLDDIR)/version.o \
	-Wl,--start-group  $(BOBJS)  -Wl,--end-group $(LDFLAGS)




# Build Version
$(BLDDIR)/version.c:
	$(PERL) $(SDK)/script/version.pl > $@
$(BLDDIR)/version.o: $(BLDDIR)/version.c
	$(CC) $(CFLAGS) -c $< -o $@

clean::
	@true

distclean:: clean

.PHONY: variable

#
# Echo variable values used for configuration
# usage: make VAR=CC variable
#
variable::
	@echo $($(VAR))


# Make.config defines remaining phony targets
.PHONY: build kernel_modules user_libs DELIVER mod bcm user
