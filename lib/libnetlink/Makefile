
include $(RTE_SDK)/mk/rte.vars.mk
LIB= libnetlink.a

CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)
CFLAGS += -I$(SRCDIR)/../../include/

SRCS-y += netlink.c

SYMLINK-y-include += libnetlink.h

LIBABIVER=1
EXPORT_MAP := libnetlink.map

include $(RTE_SDK)/mk/rte.extlib.mk
