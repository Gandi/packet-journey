ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif


include $(RTE_SDK)/mk/rte.vars.mk

O ?= $(RTE_SRCDIR)/build
EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O0 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h -DRDPDK_OFFLOAD_VLAN #-DRDPDK_DEBUG #-DRDPDK_QEMU
export EXTRA_CFLAGS

DIRS-y += lib
DIRS-y += app
DIRS-y += tests

.PHONY: default
default: all

.PHONY: test
test: default

.PHONY: reindent
reindent:
	indent -kr -ut -ts 4 */*.c */*/*.c */*.h */*/*.h

include $(RTE_SDK)/mk/rte.extsubdir.mk

