
include $(RTE_SDK)/mk/rte.extvars.mk
SHARED = libneighbour.so

CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)

SRCS-y += neighbour.c

SYMLINK-FILES-y := libneighbour.h

include $(RTE_SDK)/mk/rte.extshared.mk
