include $(RTE_SDK)/mk/rte.vars.mk

DIRS-y += libneighbour



.PHONY:test default
default: all
test:
	$(Q)for dir in $(DIRS-y); do\
		echo "== $$dir";\
		$(MAKE) -C $$dir \
			M=$(CURDIR)/$$dir/Makefile \
			O=$(BASE_OUTPUT)/$(CUR_SUBDIR)/$$dir/$(RTE_TARGET) \
			BASE_OUTPUT=$(BASE_OUTPUT) \
			CUR_SUBDIR=$(CUR_SUBDIR)/$$dir \
			S=$(CURDIR)/$$dir\
			test;\
	done

include $(RTE_SDK)/mk/rte.extsubdir.mk
