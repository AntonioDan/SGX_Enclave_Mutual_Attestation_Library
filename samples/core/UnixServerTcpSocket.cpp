/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include "NonBlockingUnixCommunicationSocket.h"
//#include "UnixCommunicationTCPSocket.h"
#include "UnixServerTcpSocket.h"

UnixServerTCPSocket::UnixServerTCPSocket(short port, const unsigned int clientTimeout) :
    m_port(port),
    m_Socket(-1),
    m_clientTimeout(clientTimeout)
{
}

UnixServerTCPSocket::~UnixServerTCPSocket() {
    if (m_Socket > 0) {        
        close(m_Socket);
    }
}

void UnixServerTCPSocket::init()
{
    /* init will always return directly with success if object was created with pre-existent socket */
    if (m_Socket > 0)
        return;

    struct sockaddr_in server_address;

    m_Socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_Socket < 0) {
        throw("Failed to create socket");
    }

    memset(&server_address, 0, sizeof(struct sockaddr_in));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = m_port;
    
    socklen_t server_len = sizeof(server_address);
    int rc = bind(m_Socket, (struct sockaddr*)&server_address, server_len);
    if (rc < 0) {
        close(m_Socket);
        throw("Failed to create socket");
    }

    rc = listen(m_Socket, 32);
    if (rc < 0) {
        close(m_Socket);
        throw("Error listening on socket"); 
    }
}

ICommunicationSocket* UnixServerTCPSocket::accept()
{
    int client_sockfd = (int) TEMP_FAILURE_RETRY(::accept(m_Socket, NULL, NULL));
    if (client_sockfd < 0)
        return NULL;

    NonBlockingUnixCommunicationSocket* sock = new NonBlockingUnixCommunicationSocket(client_sockfd);

    bool initializationSuccessfull = sock->init();

    if (initializationSuccessfull == false)
    {
        delete sock;
        sock = NULL;
    }
    else
    {        
        sock->setTimeout(m_clientTimeout);
    }

    return sock;
}
