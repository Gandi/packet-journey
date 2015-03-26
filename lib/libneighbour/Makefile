
include $(RTE_SDK)/mk/rte.vars.mk

LIB = libneighbour.a

CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)
CFLAGS += -I$(SRCDIR)/../../include/

SRCS-y += neighbour.c

SYMLINK-y-include += libneighbour.h

include $(RTE_SDK)/mk/rte.extlib.mk
