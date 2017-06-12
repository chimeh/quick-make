export HSL_DIR := $(realpath $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
ZEBOS := $(realpath $(HSL_DIR)/..)
HSL_RELATE_CTC_DIR := ../../zeb/hsl/
INCLUDEDIR := $(ZEBOS)


ifndef MODULE
MODULE :=hsl
endif

INCLUDE = 
INCLUDE += -I$(INCLUDEDIR)/platform/linux
INCLUDE += -I$(INCLUDEDIR)/hsl
INCLUDE += -I$(INCLUDEDIR)/hsl/L2
INCLUDE += -I$(INCLUDEDIR)/hsl/L3
INCLUDE += -I$(INCLUDEDIR)/hsl/common
INCLUDE += -I$(INCLUDEDIR)/hsl/ipmc
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/L2
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/linux
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/linux/L2
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/linux/L3
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/linux/L4
INCLUDE += -I$(INCLUDEDIR)/hal
INCLUDE += -I$(INCLUDEDIR)/hal/L2
INCLUDE += -I$(INCLUDEDIR)/hal/L3
INCLUDE += -I$(INCLUDEDIR)/hal/hsl
INCLUDE += -I$(INCLUDEDIR)/hal/layer4
INCLUDE += -I$(INCLUDEDIR)
INCLUDE += -I$(INCLUDEDIR)/hsl/openflow
INCLUDE += -I$(INCLUDEDIR)/hal/hsl
INCLUDE += -I$(INCLUDEDIR)/hal/MPLS

INCLUDE += -I$(INCLUDEDIR)/../../include/
INCLUDE += -I$(INCLUDEDIR)/../../include/fwdu
INCLUDE += -I$(INCLUDEDIR)/hsl/ctc/L3
EXTRA_CFLAGS += ${INCLUDE}
EXTRA_CFLAGS += -g    -DSDK_IN_KERNEL


#hsl/
HSL_SRCS := $(shell find $(INCLUDEDIR)/hsl -maxdepth 1  -name "*.c")
HSL_OBJS := $(patsubst %.c,%.o,$(HSL_SRCS))
HSL_OBJS := $(addprefix $(HSL_RELATE_CTC_DIR), $(subst $(INCLUDEDIR)/hsl/,,$(HSL_OBJS)))

$(MODULE)-objs += ${HSL_OBJS}

#hsl/common/
COM_SRCS := $(shell find $(INCLUDEDIR)/hsl/common  -name "*.c" )
COM_OBJS := $(patsubst %.c,%.o,$(COM_SRCS))
COM_OBJS := $(addprefix $(HSL_RELATE_CTC_DIR), $(subst $(INCLUDEDIR)/hsl/,,$(COM_OBJS)))

$(MODULE)-objs += ${COM_OBJS}

#hsl/L2
L2_SRCS := $(shell find $(INCLUDEDIR)/hsl/L2  -name "*.c" )
L2_OBJS := $(patsubst %.c,%.o,$(L2_SRCS))
L2_OBJS := $(addprefix $(HSL_RELATE_CTC_DIR),$(subst $(INCLUDEDIR)/hsl/,,$(L2_OBJS)))

$(MODULE)-objs += ${L2_OBJS}

#hsl/L3
L3_SRCS := $(shell find $(INCLUDEDIR)/hsl/L3  -name "*.c" )
L3_OBJS := $(patsubst %.c,%.o,$(L3_SRCS))
L3_OBJS += $(HSL_DIR)/ctc/L3/hsl_ctc_nh.o 
L3_OBJS += $(HSL_DIR)/ctc/L3/hsl_ctc_fib.o
L3_OBJS += $(HSL_DIR)/ctc/L3/hsl_ctc_ipmc.o
L3_OBJS := $(addprefix $(HSL_RELATE_CTC_DIR), $(subst $(INCLUDEDIR)/hsl/,,$(L3_OBJS)))

$(MODULE)-objs += ${L3_OBJS}

CTC_OBJS :=

CTC_OBJS += $(HSL_DIR)/ctc/linux/hsl_os.o \
				  $(HSL_DIR)/hsl.o\
				  $(HSL_DIR)/hsl_logger.o \
				  $(HSL_DIR)/ctc/linux/hsl_comm.o \
				  $(HSL_DIR)/ctc/linux/hsl_msg.o \
				  $(HSL_DIR)/ctc/hsl_ctc_pkt.o \
				  $(HSL_DIR)/ctc/linux/hsl_ctc_ifhdlr.o	\
				  $(HSL_DIR)/hsl_ifmgr.o 

CTC_OBJS += $(HSL_DIR)/ctc/linux/L2/hsl_af_lacp.o \
				  $(HSL_DIR)/ctc/linux/L2/hsl_af_stp.o \
				  $(HSL_DIR)/ctc/linux/L2/hsl_l2_sock.o \
				  $(HSL_DIR)/ctc/L2/hsl_ctc_l2.o \
				  $(HSL_DIR)/ctc/hsl_ctc_resv_vlan.o \
				  $(HSL_DIR)/ctc/linux/L3/native/hsl_stack.o\
				  $(HSL_DIR)/ctc/linux/L3/hsl_eth_drv.o	\
				  $(HSL_DIR)/ctc/linux/L4/bcm_cap.o		\
				  $(HSL_DIR)/ctc/linux/L4/acl_build.o	\
				  $(HSL_DIR)/ctc/linux/L4/bcm_cap_show.o	\
				  $(HSL_DIR)/ctc/linux/L4/mac_acl_build.o	\
				  $(HSL_DIR)/ctc/linux/L4/qos_build.o	\
				  $(HSL_DIR)/ctc/linux/L4/auth_rule_build.o	\
				  $(HSL_DIR)/ctc/linux/L4/bcm_l4_debug.o	\
				  $(HSL_DIR)/ctc/L2/hsl_ctc_fdb.o			
				  

CTC_HSL_SRCS := $(shell find $(HSL_DIR)/ctc -maxdepth 1 -name "*.c" )
CTC_OBJS += $(patsubst %.c,%.o,$(CTC_HSL_SRCS))
CTC_OBJS += $(HSL_DIR)/ctc/hsl_ctc.o

CTC_OBJS +=  $(HSL_DIR)/ctc/oss_log.o \
				$(HSL_DIR)/ctc/oss_memory.o\
				$(HSL_DIR)/ctc/oss_semaphore.o
				
$(MODULE)-objs += $(addprefix $(HSL_RELATE_CTC_DIR), $(subst $(INCLUDEDIR)/hsl/,,$(CTC_OBJS)))
