ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

PKTJ_QEMU = 0
export PKTJ_QEMU

# by default we build in build/
O ?= $(RTE_SRCDIR)/build

# if we build for qemu, enable as much debug as possible
ifeq ($(PKTJ_QEMU),1)
EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O0 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h -DPKTJ_DEBUG -DPKTJ_QEMU -DL3FWDACL_DEBUG
else
EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O3 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h
endif
export EXTRA_CFLAGS

DIRS-y += lib
DIRS-y += app
DIRS-y += tests

.PHONY: default
default: all

.PHONY: test
test: default

# we use clang-format-3.7, format your code before commiting
.PHONY: format
format:
	clang-format -i */*.h */*.c

include $(RTE_SDK)/mk/rte.extsubdir.mk

