include buildenv.mk

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
		Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		Build_Mode = HW_PRERELEASE
else
		Build_Mode = HW_RELEASE
endif
endif

ifeq ($(SGX_MODE), SIM)
ifeq ($(SGX_DEBUG), 1)
		Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		Build_Mode = SIM_PRERELEASE
else
		Build_Mode = SIM_RELEASE
endif
endif

SUB_DIR := tqvl tea_key_exchange_initiator tea_key_exchange_responder enclaveinitiator enclaveresponder uea_key_exchange_initiator uea_key_exchange_responder samples/appinitiator samples/appresponder

ifneq ($(OUTDIR),)
$(shell mkdir -p $(OUTDIR))
endif

ifneq ($(LIBDIR),)
$(shell mkdir -p $(LIBDIR))
endif

.PHONY: all clean

all:
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir; \
	done
	cp config/$(EASERVERCONF) bin/
	cp config/$(QEIDENTITYCONF) bin/
	cp config/$(QVEIDENTITYCONF) bin/
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in hardware debug mode."
else ifeq ($(Build_Mode), HW_RELEAESE)
	@echo "The project has been built in hardware release mode."
else ifeq ($(Build_Mode), HW_PRERELEAESE)
	@echo "The project has been built in hardware pre-release mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in simulation debug mode."
else ifeq ($(Build_Mode), SIM_RELEAESE)
	@echo "The project has been built in simulation release mode."
else ifeq ($(Build_Mode), SIM_PRERELEAESE)
	@echo "The project has been built in simulation pre-release mode."
endif

clean:
	@rm -rf $(OUTDIR)
	@rm -rf $(LIBDIR)

	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done
	rm -f util/*.o core/*.o
	
