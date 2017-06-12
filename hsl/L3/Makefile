############################################################
##
## HSL Sub Module Makefile
##
############################################################

include ${SDK}/make/Make.config
include ../bcm.rule

CFLAGS	+= -Wall -O2 -I$(SDK)/src
SRCS = hsl_fib.c \

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
