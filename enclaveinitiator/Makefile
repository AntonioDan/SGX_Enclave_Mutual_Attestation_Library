include ../buildenv.mk

ENCLAVE_NAME = libenclaveinitiator.so
TARGET = libenclaveinitiator.signed.so

Enclave_Cpp_Files := enclaveinitiator.cpp
#Enclave_Cpp_Files += ../util/sgx_ea.cpp
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_Config_File := enclave.xml

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

Enclave_Include_Paths = -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(TOPDIR)/common/inc -I$(TOPDIR)/inc 
Enclave_C_Flags := -O2 -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

Enclave_Link_Flags := -shared -O2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(TOPDIR)/lib \
        -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -lsgx_tea_key_exchange_initiator -lsgx_tqvl -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 \
        -Wl,--version-script=enclave.lds

all: $(TARGET)
       
$(TARGET): enclaveinitiator_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -MMD -o $(ENCLAVE_NAME) $(Enclave_Link_Flags)	
	$(SGX_ENCLAVE_SIGNER) sign -key isv_private_key.pem -enclave $(ENCLAVE_NAME) -out $@ -config $(Enclave_Config_File)
	@cp $@ $(TOPDIR)/$(OUTDIR)/

$(Enclave_Cpp_Objects): %.o: %.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c -MMD $< -o $@

enclaveinitiator_t.o: enclaveinitiator_t.c
	$(CC) $(Enclave_C_Flags) -c -MMD $< -o $@

enclaveinitiator_t.c: $(SGX_EDGER8R) enclaveinitiator.edl 
	$(SGX_EDGER8R) --use-prefix --trusted enclaveinitiator.edl --search-path $(SGX_SDK)/include --search-path $(TOPDIR)/tea_key_exchange_initiator --search-path $(TOPDIR)/tqvl

clean:
	$(RM) *.o *.d enclaveinitiator_t.* $(ENCLAVE_NAME) $(TARGET)

.PHONY: all clean
