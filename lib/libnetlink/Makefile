
include $(RTE_SDK)/mk/rte.extvars.mk
SHARED = libnetlink.so

CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)

SRCS-y += netlink.c

SYMLINK-y-include := libnetlink.h

include $(RTE_SDK)/mk/rte.extshared.mk
