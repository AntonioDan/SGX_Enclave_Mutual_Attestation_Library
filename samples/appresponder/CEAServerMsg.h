#ifndef _CEASERVERMSG_H_
#define _CEASERVERMSG_H_

#include "sgx_ea.h"
#include "ICommunicationSocket.h"

#pragma pack(push,1)
struct EAServerMsg
{
    uint8_t *message;
    ICommunicationSocket *socket;

#ifdef __cplusplus
    public:
        EAServerMsg(uint8_t * msg, ICommunicationSocket * sock) : message(msg), socket(sock) {}
        ~EAServerMsg(){}

    private:
        EAServerMsg(const EAServerMsg&);
        EAServerMsg& operator=(const EAServerMsg&);
#endif
};

#pragma pack(pop)
#endif
