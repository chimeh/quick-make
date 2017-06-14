
#
LOCALDIR = systems/linux/kernel/modules/bcm-diag-full

include ${SDK}/make/Make.config

DIAG = libdiag.a
ifdef ROBO_CHIPS
DIAG += libdiagrobo.a
endif

ifdef ESW_CHIPS
DIAG += libdiag_esw.a
endif

ifdef SBX_CHIPS
DIAG += libdiag_sbx.a
endif

ifdef EA_CHIPS
DIAG += libdiag_ea.a
endif

ifdef DPP_CHIPS
DIAG += libdiag_dpp.a
endif

ifdef DFE_CHIPS
DIAG += libdiag_dfe.a libdiag_dcmn.a
else
ifdef DPP_CHIPS
DIAG += libdiag_dcmn.a
endif
endif

DIAG_LIBS = \
	${DIAG} \
	${COND_LIB_BCMX_DIAG} \
	${COND_LIB_TEST} \
	$(APPL_LIBS) \
	libkern.a \
	libsal_appl.a \
	${COND_LIB_EDITLINE} \
	${COND_LIB_DIAG_APS} \
	libsal_appl_plat.a 

BCM_LIBS = $(DIAG_LIBS) $(DRV_LIBS) $(COND_LIB_ETH_DRV)
BCM_LIBS_BLD = $(addprefix $(LIBDIR)/,$(BCM_LIBS))
ifdef BUILD_MACSEC
BCM_LIBS_BLD += ${DIAG_EXT_LIBS}
else
BCM_LIBS_BLD += ${EXTERNAL_LIBS}
endif


ifneq ($(kernel_version),2_6)
MODULE = $(LIBDIR)/linux-bcm-diag-full.o
else
KERNEL_MODULE_DIR = kernel_module

THIS_MOD_NAME := linux-bcm-diag-full
MODULE = $(LIBDIR)/$(THIS_MOD_NAME).o
KMODULE = $(LIBDIR)/$(THIS_MOD_NAME).ko

build: $(MODULE) $(KMODULE)
endif

KBUILD_EXTRA_SYMBOLS := ${BLDDIR}/../../../../bde/linux/kernel/kernel_module/Module.symvers
KBUILD_EXTRA_SYMBOLS += ${BLDDIR}/../uk-proxy/kernel_module/Module.symvers

# BCM Diag Shell

$(MODULE): $(BLDDIR)/.tree $(BOBJS) $(BCM_LIBS_BLD) $(BLDDIR)/version.o
	$(LD) $(MODULE_LDFLAGS) -r -d $(BOBJS) --start-group $(BCM_LIBS_BLD) --end-group $(BLDDIR)/version.o -o $@
ifeq ($(kernel_version),2_6)
$(KMODULE): $(MODULE)
	rm -fr $(BLDDIR)/$(KERNEL_MODULE_DIR)
	mkdir $(BLDDIR)/$(KERNEL_MODULE_DIR)
	cp ${SDK}/make/Makefile.linux-kmodule-2_6 $(BLDDIR)/$(KERNEL_MODULE_DIR)/Makefile
	cat ${KBUILD_EXTRA_SYMBOLS} > $(BLDDIR)/$(KERNEL_MODULE_DIR)/Module.symvers
	MOD_NAME=$(THIS_MOD_NAME) $(MAKE) -C $(BLDDIR)/$(KERNEL_MODULE_DIR) $(THIS_MOD_NAME).ko
endif

# Build version

${BLDDIR}/version.c: ${BLDDIR}/.tree $(BOBJS) $(BCM_LIBS_BLD)
	${PERL} ${SDK}/tools/version.pl > $@
${BLDDIR}/version.o: ${BLDDIR}/version.c
	${CC} ${CFLAGS} -c $< -o $@

# Make.depend is before clean:: so that Make.depend's clean:: runs first.

include ${SDK}/make/Make.depend

clean::
	$(RM) $(BLDDIR)/version.c $(BLDDIR)/version.o
	$(RM) $(BOBJS) $(MODULE)

ifeq ($(kernel_version),2_6)
.PHONY: build
endif
