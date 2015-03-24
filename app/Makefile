# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = l3fwd

# all source are stored in SRCS-y
SRCS-y := main.c 
SRCS-y += control.c
SRCS-y += $(RTE_OUTPUT)/../../lib/libneighbour/$(RTE_TARGET)/lib/libneighbour.a
SRCS-y += $(RTE_OUTPUT)/../../lib/libnetlink/$(RTE_TARGET)/lib/libnetlink.a

#SRCS-y += lib/libnetlink/netlink.so
#SRCS-y += lib/libneighbour/neighbour.so
#
#CFLAGS += -I$(RTE_SRCDIR)/include

CFLAGS += -O3 $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(RTE_SRCDIR)/../lib/libneighbour/
CFLAGS += -I$(RTE_SRCDIR)/../lib/libnetlink/


LDFLAGS += -lc -lpthread -ldl
#LDFLAGS += -lneighbour -L$(RTE_OUTPUT)/lib

DEPDIR-y := lib

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk

#PREBUILD+=$(RTE_OUTPUT)/lib/libneighbour.so.0.0.1

#include $(RTE_SDK)/mk/rte.extlib.mk
#$(RTE_OUTPUT)/lib/libneighbour.so.0.0.1: lib/libneighbour/neighbour.o
#	$(LINK.) -shared $(LDFLAGS) -Wl,-soname,libneighbour.so.0 -c $@ $^

#.PHONY: reindent
#reindent:
#	indent -kr -ut -ts 4 $(SRCS-y)
