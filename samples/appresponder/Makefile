include ../../buildenv.mk

TARGET = enclaveattest_responder 

RM = rm -f

INC = -I$(SGX_SDK)/include \
	  -I$(TOPDIR)/common/inc \
	  -I$(TOPDIR)/util/inc \
	  -I../util/inc \
	  -I../core/inc \
	  -I$(RAPIDJSONINC) 

LIB := -lpthread -Wl,-rpath . -lsgx_uea_key_exchange_responder -L$(TOPDIR)/$(OUTDIR)
CXXFLAGS += $(INC) 
CFLAGS += $(INC) 

####################### App Objects ##################
all: $(TARGET)

SRC_CPP=$(wildcard *.cpp)
SRC_CPP += ../core/Thread.cpp
SRC_CPP += ../core/SocketTranslator.cpp
SRC_CPP += ../core/CSelector.cpp
SRC_CPP += ../core/UnixServerSocket.cpp
SRC_CPP += ../core/UnixServerTcpSocket.cpp
SRC_CPP += ../core/UnixCommunicationSocket.cpp
SRC_CPP += ../core/NonBlockingUnixCommunicationSocket.cpp
SRC_CPP += ../util/parseconfig.cpp
#SRC_CPP += ../util/CSGXECDSAQuote.cpp
#SRC_CPP += ../util/sgx_ea.cpp

SRC_C = $(wildcard *.c)
SRC_C += ../../util/se_trace.c
SRC_OBJ += $(SRC_CPP:.cpp=.o)
SRC_OBJ += $(SRC_C:.c=.o)

#$(TARGET): enclaveresponder_u.o $(SRC_OBJ)
$(TARGET): $(SRC_OBJ)
	$(CXX) $^ $(LIB) -o $@
	@mv $@ $(TOPDIR)/$(OUTDIR)/

clean:
	$(RM) $(TARGET) *.o ../core/*.o ../util/*.o *_u.c *_u.h

.PHONY = all clean
