ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# all source are stored in SRCS-y
SRCS-y := main.c packet_processor.c  

CFLAGS += $(WERROR_FLAGS)

EXTRA_CFLAGS += -O0 -g -w -Wfatal-errors

#include $(RTE_SDK)/mk/rte.extlib.mk
include $(RTE_SDK)/mk/rte.extobj.mk
