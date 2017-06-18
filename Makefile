ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

BUILD_TARGET ?= debug
export BUILD_TARGET

# by default we build in build/
O ?= $(RTE_SRCDIR)/build

EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O3 -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h

ifeq ($(BUILD_TARGET),qemu)
EXTRA_CFLAGS +=  -DPKTJ_DEBUG -DPKTJ_QEMU -DL3FWDACL_DEBUG -DRTE_LOG_LEVEL=8
endif
ifeq ($(BUILD_TARGET),release)
EXTRA_CFLAGS +=  -DRTE_LOG_LEVEL=3
endif
ifeq ($(BUILD_TARGET),debug)
EXTRA_CFLAGS +=  -DPKTJ_DEBUG -DRTE_LOG_LEVEL=8 -DL3FWDACL_DEBUG
endif
export EXTRA_CFLAGS

DIRS-y += lib
DIRS-y += app
DIRS-y += tests

DEPDIRS-tests = lib

.PHONY: default
default: all

.PHONY: test
test: default

.PHONY: help
help:
	@cat doc/build-commands.txt

# we use clang-format-3.7, format your code before commiting
.PHONY: format
format:
	clang-format -i */*.h */*.c

include $(RTE_SDK)/mk/rte.extsubdir.mk

