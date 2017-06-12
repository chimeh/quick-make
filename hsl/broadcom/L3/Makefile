############################################################
##
## HSL Sub Module Makefile
##
############################################################

include ${SDK}/make/Make.config
include ../../bcm.rule

CFLAGS	+= -Wall -O2 -I$(SDK)/src
LIBS	+= 
SOURCES = hsl_bcm_fib.c 

OBJECTS = $(SOURCES:.c=.o)

TARGET_MY = bcm_l3

all:    $(TARGET_MY)

$(TARGET_MY): $(OBJECTS)
#	$(CC) $(OBJECTS) $(LIBS) -o $@
#	$(STRIP) $@

%.o: %.c
	@echo "CFLAGS:$(CFLAGS)..."
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	-rm -f $(OBJECTS) core
#	-rm -f $(TARGET_MY)

depend:
	@echo start to build dependances in .depend
	@for i in $(SOURCES); do \
	$(CC) -MM $(CFLAGS) $(INCLUDE) $$i; \
	done > .tmpdepend; \
	mv -f .tmpdepend .depend 
ifeq (.depend,$(wildcard .depend))
	include .depend
endif
