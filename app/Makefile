include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = l3fwd

# all source are stored in SRCS-y
SRCS-y := main.c 
SRCS-y += control.c
SRCS-y += kni.c
SRCS-y += cmdline.c
SRCS-y += acl.c
SRCS-y += config.c
SRCS-y += cmdline_helpers.c
SRCS-y += $(RTE_OUTPUT)/../../lib/libneighbour/$(RTE_TARGET)/lib/libneighbour.a
SRCS-y += $(RTE_OUTPUT)/../../lib/libnetlink/$(RTE_TARGET)/lib/libnetlink.a

#SRCS-y += lib/libnetlink/netlink.so
#SRCS-y += lib/libneighbour/neighbour.so
#
#CFLAGS += -I$(RTE_SRCDIR)/include

CFLAGS += -O0 -g $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(RTE_SRCDIR)/../lib/libneighbour/
CFLAGS += -I$(RTE_SRCDIR)/../lib/libnetlink/

LDFLAGS += -lc -lpthread -ldl
#LDFLAGS += -lneighbour -L$(RTE_OUTPUT)/lib

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

.PHONY: default test
default: all
test:


include $(RTE_SDK)/mk/rte.extapp.mk


