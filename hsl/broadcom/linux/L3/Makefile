#########################################################################
##
## Makefile of HSL
##
#########################################################################

include ${SDK}/make/Make.config
include ../../../bcm.rule

CFLAGS  += -Wall -O2 -I$(SDK)/src
SRCS = hsl_eth_drv.c
OBJS = $(SRCS:.c=.o)
TARGET_MY_MY = linux

SUBDIRS = native

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
