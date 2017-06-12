############################################################
##
## HSL Sub Module Makefile
##
############################################################

include ${SDK}/make/Make.config
include ../../bcm.rule

CFLAGS	+= -Wall -O2 -I$(SDK)/src
LIBS	+= 
SRCS = hsl_bcm_auth.c \
		hsl_bcm_fdb.c \
		hsl_bcm_l2.c  \
		hsl_bcm_pvlan.c \
		hsl_bcm_vlanclassifier.c \
		hsl_bcm_vlanstack.c

OBJS = $(SRCS:.c=.o)

TARGET_MY = bcm_l2 

all: $(TARGET_MY)

$(TARGET_MY): $(OBJS)
#	$(CC) $(OBJECTS) $(LIBS) -o $@
#	$(STRIP) $@

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	-rm -f $(OBJS) core
	-rm -f $(TARGET_MY)

depend:
	@echo start to build dependances in .depend
	@for i in $(SRCS); do \
	$(CC) -MM $(CFLAGS) $(INCLUDE) $$i; \
	done > .tmpdepend; \
	mv -f .tmpdepend .depend 
ifeq (.depend,$(wildcard .depend))
	include .depend
endif
