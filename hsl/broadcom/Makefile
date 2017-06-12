#########################################################################
##
## Makefile of HSL
##
#########################################################################

include ${SDK}/make/Make.config
include ../bcm.rule

CFLAGS  += -I$(SDK)/src
SRCS = hsl_bcm_acl.c \
		hsl_bcm_if.c \
		hsl_bcm_lacp.c \
		hsl_bcm_qos.c \
		oss_log.c \
		hsl_bcm.c \
		hsl_bcm_ifcb.c \
		hsl_bcm_mc.c \
		hsl_bcm_resv_vlan.c \
		oss_memory.c \
		hsl_bcm_ifmap.c \
		hsl_bcm_pkt.c  \
		hsl_bcm_vlan_access_map.c \
		oss_semaphore.c  \
		hsl_bcm_optical_module.c

OBJS = $(SRCS:.c=.o)
TARGET_MY = broadcom

SUBDIRS = L2 L3 linux

%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

$(TARGET_MY): $(OBJS)
	@for dir in ${SUBDIRS}; do \
	echo "Making all in $$dir"; \
	(cd $$dir; $(MAKE)) || exit 1; \
	done


clean:
	@for dir in ${SUBDIRS}; do \
	echo "Making all in $$dir"; \
	(cd $$dir; $(MAKE) clean) || exit 1; \
	done
	rm -rf $(OBJS)

depend:
	@for dir in ${SUBDIRS}; do \
	echo "Making all in $$dir"; \
	(cd $$dir; $(MAKE) depend) || exit 1; \
	done
