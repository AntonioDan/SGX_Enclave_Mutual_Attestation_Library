#
# INTEL CONFIDENTIAL
# Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its suppliers
# or licensors. Title to the Material remains with Intel Corporation or its
# suppliers and licensors. The Material contains trade secrets and proprietary
# and confidential information of Intel or its suppliers and licensors. The
# Material is protected by worldwide copyright and trade secret laws and treaty
# provisions. No part of the Material may be used, copied, reproduced, modified,
# published, uploaded, posted, transmitted, distributed, or disclosed in any
# way without Intel's prior express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or delivery
# of the Materials, either expressly, by implication, inducement, estoppel or
# otherwise. Any license under such intellectual property rights must be
# express and approved by Intel(R) in writing.
#

include ../buildenv.mk

CXXFLAGS += -Werror

INCLUDE += -I$(TOPDIR)/common/inc \
		   -I../util/inc \
		   -I$(RAPIDJSONINC)\

SGXINCLUDE = -I$(SGX_SDK)/include/

SRC := $(wildcard *.cpp)
#SRC += ../util/sgx_ea.cpp
SRC += ../util/CSGXECDSAQuote.cpp
SRC += ../util/CSGXECDSAQuoteVerifier.cpp
SRC += ../util/JsonParser.cpp
SRC += ../util/TimeUtils.cpp
SRC += ../util/CEAQEIdentity.cpp
#SRC += ../core/UnixCommunicationTCPSocket.cpp
OBJ := $(sort $(SRC:.cpp=.o))

LIBS := -lsgx_urts -lsgx_uae_service -lsgx_dcap_quoteverify -L$(SGX_SDK)/lib64

LIBNAME := libsgx_uea_key_exchange_responder.so

.PHONY: all
all: $(LIBNAME)
	cp $(LIBNAME) $(TOPDIR)/$(OUTDIR)/

$(LIBNAME): enclaveresponder_u.o $(OBJ) 
	$(CXX) $^ $(LIBS) -lstdc++ -shared -o $@

$(OBJ): %.o :%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(SGXINCLUDE) -c $< -o $@

#../util/TimeUtils.o:../util/TimeUtils.cpp
#	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

enclaveresponder_u.o:enclaveresponder_u.c
	$(CC) $(CFLAGS) $(INCLUDE) $(SGXINCLUDE) -c $< -o $@

enclaveresponder_u.c: ../enclaveresponder/enclaveresponder.edl	
	$(SGX_EDGER8R) --use-prefix --untrusted $< --search-path $(TOPDIR)/tea_key_exchange_responder --search-path $(SGX_SDK)/include --search-path $(TOPDIR)/tqvl

.PHONY: clean
clean:
	@$(RM) $(OBJ) $(LIBNAME) enclaveinitiator_u.* enclaveresponder_u.* ../util/*.o

.PHONY: rebuild
rebuild: 
	$(MAKE) clean 
	$(MAKE) all
