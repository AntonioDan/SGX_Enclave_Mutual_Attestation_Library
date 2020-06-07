#ifndef _UNIXSERVERTCPSOCKET_H_
#define _UNIXSERVERTCPSOCKET_H_

#include "IServerSocket.h"

class UnixServerTCPSocket : public IServerSocket {
    public:
        UnixServerTCPSocket(short port, const unsigned int clientTimeout = 0);
        ~UnixServerTCPSocket();

    public:
        virtual void                    init();
        virtual ICommunicationSocket*   accept();

        virtual int getSockDescriptor() { return m_Socket; }
    
    private:
        short m_port;
        int m_Socket;   
        unsigned int m_clientTimeout;
};

#endif