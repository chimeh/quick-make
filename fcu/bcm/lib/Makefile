
#
# Makefile for Switch on a Chip (SOC) driver and diagnostics
#

include ${SDK}/mk/Make.config

export TARGET
export BLDDIR
export LIBDIR


subdirs = customer sal
ifeq (unix,$(findstring unix,${targetbase}))
subdirs += halu
endif

override MAKEFLAGS += TARGET=$(TARGET)

include ${SDK}/mk/Make.subdirs


