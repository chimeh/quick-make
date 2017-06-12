#########################################################################
##
## Makefile of HSL
##
#########################################################################

include ${SDK}/make/Make.config
include ../../../bcm.rule

CFLAGS  += -Wall -O2 -I$(SDK)/src
SRCS = acl_build.c qos_build.c bcm_cap.c bcm_cap_show.c bcm_l4_debug.c of_acl_build.c mac_acl_build.c mirror_build.c auth_rule_build.c
OBJS = $(SRCS:.c=.o)
TARGET_MY_MY = linux



%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

$(TARGET_MY_MY): $(OBJS)
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
