#ifndef _CEASERVICENETWORK_H__
#define _CEASERVICENETWORK_H_

#include <string>

#include "CEAServiceTranslator.h"
#include "ICommunicationSocket.h"

class CEAServiceNetwork : public CEAServiceTranslator {
    public:
        CEAServiceNetwork(const char *);
        CEAServiceNetwork(std::string, short);
        ~CEAServiceNetwork();

    public:
        size_t sendMessage(uint8_t * message, size_t size);
        uint8_t * recvMessage();
        uint8_t * sendandrecv(uint8_t * message, size_t size);
        void init();

    private:
        //UnixCommunicationSocket * m_socket;
        ICommunicationSocket *m_socket;
        const char * m_socketbase;
        std::string m_server_ip;
        short m_port;

    private:
        CEAServiceNetwork(const CEAServiceNetwork&);
        CEAServiceNetwork& operator=(const CEAServiceNetwork&);
};
#endif
