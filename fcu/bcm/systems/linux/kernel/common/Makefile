

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

user-override=unix-user

ifeq (,$(platform))
$(error Makefile: error: Internal error: platform variable is not set)
else

override-target=linux-$(platform)
include $(SDK)/make/Make.config
endif

ifeq (,$(kernel_version))
kernel_version=2_6
endif

ifeq ($(kernel_version),2_6)
KOBJ=ko
else
KOBJ=o
endif

BCM_PROXY=$(DEST_DIR)/bcm.user.proxy

lmsc_platform=$(platform)

ifeq (2.6.24.4, $(KERN_VER))
lmsc_platform=$(platform).2.6.24
endif

ifeq (3.0,$(WRS_LINUX_VERSION))
lmsc_platform=$(platform)-wr30
endif

ifeq ($(DESTDIR),)
DESTDIR=${BLDDIR}
endif

# 1 = basename
###define KERNEL_RULE
###$(DESTDIR)/$(1) : kernel_modules
###$(DEST_DIR)/$(1) : $(DESTDIR)/$(1) | $(DEST_DIR)
###	cp $(DESTDIR)/$(1) $$@
###endef


LOCAL_DESTDIR :=$(SDK)/systems/linux/kernel/$(platform)

BCM_PROXY_LOCAL :=$(LOCAL_DESTDIR)/bcm.user.proxy
###KERNEL_BDE_LOCAL :=$(LOCAL_DESTDIR)/linux-kernel-bde.$(KOBJ)
KERNEL_CORE_LOCAL :=$(LOCAL_DESTDIR)/linux-bcm-core.$(KOBJ)
KERNEL_XXX_LOCAL :=$(LOCAL_DESTDIR)/linux-xxx.$(KOBJ)
###KERNEL_PROXY_LOCAL :=$(LOCAL_DESTDIR)/linux-uk-proxy.$(KOBJ)
###KERNEL_DIAG_FULL_LOCAL :=$(LOCAL_DESTDIR)/linux-bcm-diag-full.$(KOBJ)
###KERNEL_NET_LOCAL :=$(LOCAL_DESTDIR)/linux-bcm-net.$(KOBJ)
###KERNEL_DIAG_LOCAL :=$(LOCAL_DESTDIR)/linux-bcm-diag.$(KOBJ)

###KERNEL_BDE :=$(DEST_DIR)/linux-kernel-bde.$(KOBJ)
KERNEL_CORE:=$(DEST_DIR)/linux-bcm-core.$(KOBJ)
KERNEL_XXX:=$(DEST_DIR)/linux-xxx.$(KOBJ)
###KERNEL_PROXY :=$(DEST_DIR)/linux-uk-proxy.$(KOBJ)
###KERNEL_DIAG_FULL :=$(DEST_DIR)/linux-bcm-diag-full.$(KOBJ)
###KERNEL_NET:=$(DEST_DIR)/linux-bcm-net.$(KOBJ)
###KERNEL_DIAG:=$(DEST_DIR)/linux-bcm-diag.$(KOBJ)

###_KERNEL_BDE:=$(DESTDIR)/linux-kernel-bde.$(KOBJ)
_KERNEL_CORE:=$(DESTDIR)/linux-bcm-core.$(KOBJ)
_KERNEL_XXX:=$(DESTDIR)/linux-xxx.$(KOBJ)
###_KERNEL_PROXY:=$(DESTDIR)/linux-uk-proxy.$(KOBJ)
###_KERNEL_DIAG_FULL:=$(DESTDIR)/linux-bcm-diag-full.$(KOBJ)
###_KERNEL_NET:=$(DESTDIR)/linux-bcm-net.$(KOBJ)
###_KERNEL_DIAG:=$(DESTDIR)/linux-bcm-diag.$(KOBJ)

_KERNEL_TARGETS:=$(_KERNEL_XXX) $(_KERNEL_CORE) $(_KERNEL_PROXY)

# Modules must be built in load order to ensure correct module versioning
KERNEL_TARGETS:=$(KERNEL_XXX) $(KERNEL_CORE)

ifeq ($(NO_LOCAL_TARGETS),)
LOCAL_TARGETS :=$(KERNEL_XXX_LOCAL) $(KERNEL_CORE_LOCAL) $(KERNEL_PROXY_LOCAL)
KERNEL_TARGETS += $(LOCAL_TARGETS)

# Rule to make local target
define LOCAL_TARGET_DEF
$(1) : $(DESTDIR)/$(notdir $(1))
	$(OBJCOPY) --strip-debug $$? $$@
endef
endif

ifeq (,$(findstring DELIVER,$(MAKECMDGOALS)))
all: $(KERNEL_TARGETS) user_apps link_check $(if $(NO_LOCAL_TARGETS),,$(BCM_PROXY_LOCAL))

$(KERNEL_CORE_LOCAL): $(DEST_DIR) kernel_modules 
	$(OBJCOPY) --strip-debug $$? $$@
	
###$(foreach t,$(notdir $(_KERNEL_TARGETS)),$(eval $(call KERNEL_RULE,$(t))))
$(notdir $(_KERNEL_XXX)): $(DEST_DIR) kernel_modules
$(DESTDIR)/$(_KERNEL_XXX) : 
$(DEST_DIR)/$(_KERNEL_XXX) : $(DESTDIR)/$(_KERNEL_XXX) | $(DEST_DIR)
	cp $(DESTDIR)/$(1) $$@
	

###ifeq ($(NO_LOCAL_TARGETS),)
###$(foreach t,$(LOCAL_TARGETS),$(eval $(call LOCAL_TARGET_DEF,$(t))))
###endif


$(DEST_DIR):
	mkdir -p $@

kernel_modules:
	$(MAKE) -C $(SDK)/src
	$(MAKE) -C $(SDK)/systems/linux/kernel/modules kernel_version=$(kernel_version)

$(BCM_PROXY_LOCAL) : $(BCM_PROXY)
	rm -f $@
	ln -sf $? $@

$(BCM_PROXY) : user_apps

user_apps:
	$(MAKE) -C $(SDK)/systems/linux/kernel/user/bcm-diag-proxy \
		 BCM_PROXY=$(BCM_PROXY) \
		 override-target=$(user-override) \
		 bldroot_suffix=/$(override-target)

#
# Define the set of allowable link dependencies. 
# All configurations in the LINK_CHECKS variable
# must be clean. 
#
LINK_CHECKS = $(KERNEL_BDE)
LINK_CHECKS += $(KERNEL_PROXY)
LINK_CHECKS += $(KERNEL_BDE),$(KERNEL_CORE)
LINK_CHECKS += $(KERNEL_BDE),$(KERNEL_CORE),$(KERNEL_NET)
LINK_CHECKS += $(KERNEL_BDE),$(KERNEL_CORE),$(KERNEL_PROXY),$(KERNEL_DIAG)
LINK_CHECKS += $(KERNEL_BDE),$(KERNEL_PROXY),$(KERNEL_DIAG_FULL)

link_check: kernel_modules
	$(PERL) $(SDK)/tools/lmsc.pl ferror=0 kernel=$(lmsc_platform) $(LINK_CHECKS)

clean:
	$(MAKE) -C $(SDK)/src $@
	$(MAKE) -C $(SDK)/systems/linux/kernel/modules $@
	$(MAKE) -C $(SDK)/systems/bde/linux/kernel $@
	$(MAKE) -C $(SDK)/systems/linux/kernel/user/bcm-diag-proxy \
		 BCM_PROXY=$(BCM_PROXY) \
		 override-target=$(user-override) \
		 bldroot_suffix=/$(override-target) $@
	$(RM) $(_KERNEL_TARGETS) $(KERNEL_TARGETS) $(LOCAL_TARGETS)
ifdef BUILD_MACSEC
	$(MAKE) -C ${MACSEC_HOME} MACSEC_TARGET="${targetbase}/$(targetplat)/${platform}" clean
endif

distclean: clean

.PHONY: variable user_apps



else
ifndef DELIVERY
$(error DELIVERY required)
endif

DELIVERABLES := $(filter-out  $(KERNEL_DIAG_FULL), $(KERNEL_TARGETS)) $(BCM_PROXY)

# 1= source
define DELIVERY_RULE
_DEL_TARG += $(DELIVERY)/$(notdir $(1))
$(DELIVERY)/$(notdir $(1)) : $(1)
	@mkdir -p $(DELIVERY)
	$(OBJCOPY) --strip-debug $$< $$@
endef

$(foreach f,$(DELIVERABLES),$(eval $(call DELIVERY_RULE,$(f))))

DELIVER: $(_DEL_TARG)
endif

include $(SDK)/make/Makefile.debug
# Make.config defines remaining phony targets
.PHONY: check kernel_modules user_apps kernel_targets DELIVER $(_DEL_TARG)

