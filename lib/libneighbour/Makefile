
include $(RTE_SDK)/mk/rte.extvars.mk
SHARED = libneighbour.so

CFLAGS += -I$(RTE_SDK)/build/include
CFLAGS += -I$(SRCDIR)

SRCS-y += neighbour.c

SYMLINK-y-include := libneighbour.h

include $(RTE_SDK)/mk/rte.extshared.mk
