#ifndef _CEASERVICETRANSLATOR_H_
#define _CEASERVICETRANSLATOR_H_

#include <stdint.h>
#include "sgx_ea.h"

class CEAServiceTranslator {
    public:
        virtual ~CEAServiceTranslator(){}
    public:
        virtual void init() = 0;
        virtual size_t sendMessage(uint8_t * message, size_t size) = 0;
        virtual uint8_t* recvMessage() = 0;
        virtual uint8_t* sendandrecv(uint8_t * message, size_t size) = 0;
};

#endif
