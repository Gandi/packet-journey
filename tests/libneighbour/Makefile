include $(RTE_SDK)/mk/rte.vars.mk

APP = test_libneighbour

NS := $(shell mktemp -u -t XXXXXX | sed 's@/tmp/@@')

SRCS-y += a.c

CFLAGS += -I$(BASE_OUTPUT)/lib/libneighbour/$(RTE_TARGET)/include
CFLAGS += -I$(SRCDIR)/../../include/

LDFLAGS += -L$(BASE_OUTPUT)/lib/libneighbour/$(RTE_TARGET)/lib -lneighbour

.PHONY: default test
default: all

include $(RTE_SDK)/mk/rte.extapp.mk

test: default $(RTE_OUTPUT)/output.log

SHELL:=/bin/bash -o pipefail
$(RTE_OUTPUT)/output.log: $(RTE_OUTPUT)/$(APP)
	$(Q)ip netns add $(NS)
	$(Q)ip netns exec $(NS) $(RTE_SRCDIR)/script.sh $< 2>&1| tee $@ ||\
		(ip netns del $(NS); exit 1)
	$(Q)ip netns del $(NS)


