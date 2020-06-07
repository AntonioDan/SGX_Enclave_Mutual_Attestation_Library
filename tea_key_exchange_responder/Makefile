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

INCLUDE += -I$(SGX_SDK)/include/tlibc    \
           -I$(SGX_SDK)/include \
           -I$(SGX_SDK)/include/libcxx \
		   -I$(TOPDIR)/common/inc \
		   -I$(TOPDIR)/common/inc/internal \
		   -I$(TOPDIR)/common/constant/ \

CXXFLAGS += $(ENCLAVE_CXXFLAGS)

SRC := $(wildcard *.cpp)
#SRC += ../util/sgx_ea.cpp
OBJ := $(sort $(SRC:.cpp=.o))

LIBNAME := libsgx_tea_key_exchange_responder.a

.PHONY: all
all: $(LIBNAME)
	cp $(LIBNAME) $(TOPDIR)/$(LIBDIR)/

$(LIBNAME): $(OBJ)
	$(AR) rcsD $@ $^

$(OBJ): %.o :%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE)  -c $< -o $@

.PHONY: clean
clean:
	@$(RM) $(OBJ) $(LIBNAME) *_u.c *_u.h *_t.c *_t.h

.PHONY: rebuild
rebuild: 
	$(MAKE) clean 
	$(MAKE) all
