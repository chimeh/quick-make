#########################################################################
##
## Makefile of HSL
##
#########################################################################

include ${SDK}/make/Make.config
include ../../bcm.rule

CFLAGS  += -Wall -O2 -D__HSL_MODULE__ -I$(SDK)/src
SRCS = hsl_bcm_ifhdlr.c \
		hsl_comm.c \
		hsl_msg.c \
		hsl_os.c

OBJS = $(SRCS:.c=.o)
TARGET_MY = linux

SUBDIRS = L2 L3 L4

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
