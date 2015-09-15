ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif


include $(RTE_SDK)/mk/rte.vars.mk

RDPDK_QEMU = 0
export RDPDK_QEMU

O ?= $(RTE_SRCDIR)/build
ifeq ($(RDPDK_QEMU),1)
EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O0 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h -DRDPDK_DEBUG -DRDPDK_QEMU -DL3FWDACL_DEBUG
else
EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O3 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h #-DRDPDK_DEBUG
endif
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

.PHONY: format
format:
	clang-format -i */*.h */*.c

include $(RTE_SDK)/mk/rte.extsubdir.mk

