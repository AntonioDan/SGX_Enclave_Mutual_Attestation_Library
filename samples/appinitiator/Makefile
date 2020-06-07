include ../../buildenv.mk

TARGET = enclaveattest_initiator 

RM = rm -f

INC = -I$(SGX_SDK)/include \
	  -I$(TOPDIR)/common/inc \
      -I$(TOPDIR)/util/inc \
      -I../util/inc \
	  -I../core/inc \
      -I$(RAPIDJSONINC)

LIB := -Wl,-rpath . -ldl 
#CXXFLAGS += $(INC) $(LIB)
#CFLAGS += $(INC) $(LIB)
CXXFLAGS += $(INC) 
CFLAGS += $(INC) 

####################### App Objects ##################
all: $(TARGET)

SRC_CPP=$(wildcard *.cpp)
SRC_CPP+=../core/UnixCommunicationSocket.cpp
SRC_CPP+=../core/UnixCommunicationTCPSocket.cpp
SRC_CPP+=../util/parseconfig.cpp

SRC_C=$(wildcard *.c)
SRC_C+=../../util/se_trace.c

SRC_OBJ += $(SRC_C:.c=.o)
SRC_OBJ += $(SRC_CPP:.cpp=.o)

$(TARGET): $(SRC_OBJ)
	$(CXX) $^ $(CXXFLAGS) $(LIB) -o $@
	@mv $@ $(TOPDIR)/$(OUTDIR)/

clean:
	$(RM) $(TARGET) *.o *_u.c *_u.h

.PHONY = all clean
