############################################################
##
## HSL Sub Module Makefile
##
############################################################

#include ${SDK}/make/Make.config

include ../bcm.rule

CFLAGS	+= -Wall -O2  
SRCS = hsl_avl.c \
		hsl_ether.c \
		hsl_ptree.c \
		hsl_skip.c \
		hsl_table.c \
		hsl_tlv.c \
		hsl_types.c

OBJS = $(SRCS:.c=.o)

TARGET_MY_MY = common

all: $(TARGET_MY_MY)

$(TARGET_MY_MY): $(OBJS)
#	$(CC) $(OBJECTS) $(LIBS) -o $@
#	$(STRIP) $@

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	-rm -f $(OBJS) core
	-rm -f $(TARGET_MY_MY)

depend:
	@echo start to build dependances in .depend
	@for i in $(SRCS); do \
	$(CC) -MM $(CFLAGS) $(INCLUDE) $$i; \
	done > .tmpdepend; \
	mv -f .tmpdepend .depend 
ifeq (.depend,$(wildcard .depend))
	include .depend
endif
