
include $(RTE_SDK)/mk/rte.extvars.mk
SHARED = libnetlink.so

CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)

SRCS-y += netlink.c

HEADERS-y += libnetlink.h

POSTBUILD += install-headers

.PHONY: install-headers
install-headers: $(HEADERS-y)
	mkdir -p $(BASE_OUTPUT)/include
	for file in $(HEADERS-y); do\
		rm -f $(BASE_OUTPUT)/include/$$file;\
		cp -f $$file $(BASE_OUTPUT)/include;\
	done

include $(RTE_SDK)/mk/rte.extshared.mk
