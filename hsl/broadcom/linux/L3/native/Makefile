############################################################
##
## HSL Sub Module Makefile
##
############################################################

include ${SDK}/make/Make.config

include ../../../../bcm.rule

CFLAGS	+= -Wall -O2 -I$(SDK)/src

LIBS	+= -lcrypt

SRCS = hsl_stack.c 
OBJS = $(SRCS:.c=.o)

TARGET_MY_MY = native

all: $(TARGET_MY_MY)

$(TARGET_MY_MY): $(OBJS)
#	$(CC) $(OBJECTS) $(LIBS) -o $@
#	$(STRIP) $@

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	-rm -f $(OBJS) core

depend:
	@echo start to build dependances in .depend
	@for i in $(SRCS); do \
	$(CC) -MM $(CFLAGS) $(INCLUDE) $$i; \
	done > .tmpdepend; \
	mv -f .tmpdepend .depend 
ifeq (.depend,$(wildcard .depend))
	include .depend
endif
