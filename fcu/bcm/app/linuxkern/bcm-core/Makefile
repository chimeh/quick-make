
#
LOCALDIR = app/linuxkern/bcm-core

include ${SDK}/mk/Make.config

DIAG_LIBS = \
	${APPL_LIBS} \
	libkern.a 

BCM_LIBS = 
BCM_LIBS_BLD = $(addprefix $(LIBDIR)/,$(BCM_LIBS))


ifneq ($(kernel_version),2_6)
MODULE = $(LIBDIR)/linux-bcm-core.o
else
KERNEL_MODULE_DIR = kernel_module

THIS_MOD_NAME := linux-bcm-core
MODULE = $(LIBDIR)/$(THIS_MOD_NAME).o
KMODULE = $(LIBDIR)/$(THIS_MOD_NAME).ko

build: $(MODULE) $(KMODULE)
endif

KBUILD_EXTRA_SYMBOLS := ${BLDDIR}/../../../../bde/linux/kernel/kernel_module/Module.symvers

# BCM Core Driver

$(MODULE): $(BLDDIR)/.tree $(BOBJS) $(BCM_LIBS_BLD) $(BLDDIR)/version.o
	$(LD) $(MODULE_LDFLAGS) -r -d $(BOBJS) --start-group $(BCM_LIBS_BLD) --end-group $(BLDDIR)/version.o -o $@
ifeq ($(kernel_version),2_6)
$(KMODULE): $(MODULE)
	rm -fr $(BLDDIR)/$(KERNEL_MODULE_DIR)
	mkdir $(BLDDIR)/$(KERNEL_MODULE_DIR)
	cp ${SDK}/mk/Makefile.linux-kmodule-2_6 $(BLDDIR)/$(KERNEL_MODULE_DIR)/Makefile
	MOD_NAME=$(THIS_MOD_NAME) $(MAKE) -C $(BLDDIR)/$(KERNEL_MODULE_DIR) $(THIS_MOD_NAME).ko
endif

# Build version

${BLDDIR}/version.c: ${BLDDIR}/.tree $(BOBJS) $(BCM_LIBS_BLD)
	${PERL} ${SDK}/tools/version.pl > $@
${BLDDIR}/version.o: ${BLDDIR}/version.c
	${CC} ${CFLAGS} -c $< -o $@

include ${SDK}/mk/Make.depend

# Make.depend is before clean:: so that Make.depend's clean:: runs first.

clean::
	$(RM) $(BLDDIR)/version.c $(BLDDIR)/version.o
	$(RM) $(BOBJS) $(MODULE)

ifeq ($(kernel_version),2_6)
.PHONY: build
endif
