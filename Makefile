ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif


include $(RTE_SDK)/mk/rte.vars.mk

O ?= $(RTE_SRCDIR)/build
CFLAGS += -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h
export CFLAGS

DIRS-y += lib
DIRS-y += app


include $(RTE_SDK)/mk/rte.extsubdir.mk

