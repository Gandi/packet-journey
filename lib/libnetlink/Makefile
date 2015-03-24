
include $(RTE_SDK)/mk/rte.extvars.mk
SHARED = libnetlink.so

CFLAGS += -I$(RTE_SDK)/build/include
CFLAGS += -I$(SRCDIR)

SRCS-y += netlink.c

SYMLINK-y-include := libnetlink.h

include $(RTE_SDK)/mk/rte.extshared.mk
