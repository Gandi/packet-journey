include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = pktj

# all source are stored in SRCS-y
SRCS-y := main.c 
SRCS-y += control.c
SRCS-y += kni.c
SRCS-y += cmdline.c
SRCS-y += acl.c
SRCS-y += config.c
SRCS-y += cmdline_helpers.c

#CFLAGS += -I$(RTE_SRCDIR)/include

CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(RTE_SRCDIR)/../lib/libneighbour/
CFLAGS += -I$(RTE_SRCDIR)/../lib/libnetlink/

DEPDIR-y += lib/libnetlink lib/libneighbour

LDFLAGS += -lc -lpthread -ldl
LDFLAGS += -L$(BASE_OUTPUT)/lib/libneighbour/$(RTE_TARGET)/lib -L$(BASE_OUTPUT)/lib/libnetlink/$(RTE_TARGET)/lib -lneighbour -lnetlink
ifeq ($(BUILD_TARGET),qemu)
	LDFLAGS += --wrap=virtio_recv_mergeable_pkts
endif

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

.PHONY: default test
default: all
test:

include $(RTE_SDK)/mk/rte.extapp.mk
