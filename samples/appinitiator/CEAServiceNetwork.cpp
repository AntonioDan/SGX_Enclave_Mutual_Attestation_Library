#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "se_trace.h"
#include "sgx_ea_error.h"
#include "sgx_ea.h"
#include "CEAServiceNetwork.h"
#include "UnixCommunicationSocket.h"
#include "UnixCommunicationTCPSocket.h"
#include "CEAException.h"

CEAServiceNetwork::CEAServiceNetwork(const char * sockbase) : m_socketbase(sockbase)
{
    m_socket = new UnixCommunicationSocket(m_socketbase);
}

CEAServiceNetwork::CEAServiceNetwork(std::string ip, short port) : m_server_ip(ip), m_port(port)
{
    m_socket = new UnixCommunicationTCPSocket(m_server_ip, m_port);
}

CEAServiceNetwork::~CEAServiceNetwork()
{
    if (m_socket)
        delete m_socket;
}

void CEAServiceNetwork::init()
{
    if (m_socket) {
        if (m_socket->init() == false) {
            throw NetworkException("failed to init TCP Socket");
        }
    }
}

size_t CEAServiceNetwork::sendMessage(uint8_t * message, size_t size)
{
    if (!message)
        return 0;

    if (!m_socket)
        return 0;

    size_t writesize = 0;
    size_t tmp = 0;
    
    while (writesize < size) {
        tmp = m_socket->writeRaw(reinterpret_cast<char *>(message + writesize), size - writesize);
        if (tmp == 0)
            break;

        writesize += tmp;
    }
   
    return (writesize != size) ? 0 : writesize;
}

uint8_t* CEAServiceNetwork::recvMessage()
{
    sgx_ea_msg_header_t * p_ea_msg_header = NULL;
    
    p_ea_msg_header = (sgx_ea_msg_header_t *)m_socket->readRaw(sizeof(sgx_ea_msg_header_t));
    if (!p_ea_msg_header) {
        throw NetworkException("failed to read message from socket");
    }

    uint8_t * p_content = (uint8_t *)m_socket->readRaw(p_ea_msg_header->size);
    if (!p_content) {
        delete[] p_ea_msg_header;
        throw NetworkException("failed to read message from socket");
    }

    uint8_t * p_msg = new uint8_t[p_ea_msg_header->size + sizeof(sgx_ea_msg_header_t)];
    memcpy(p_msg, (uint8_t *)p_ea_msg_header, sizeof(sgx_ea_msg_header_t));
    memcpy(p_msg + sizeof(sgx_ea_msg_header_t), p_content, p_ea_msg_header->size);

    delete[] p_ea_msg_header;
    delete[] p_content;
    
    return p_msg;
}

/* This function send message and receive response message.
 * Input parameter:
 *     uint8_t * message: this points to message buffer to be sent
 *     uint32_t size: this is sent message's size
 * 
 * Return value:
 *     when this function succeed to run, it returns a pointer to received message; otherwise it returns to NULL;
 *
 * Note:
 *     This function assume the received function starts with sgx_ea_msg_header_t.
 * 
 */
uint8_t * CEAServiceNetwork::sendandrecv(uint8_t * message, size_t size)
{
    size_t sendsize;

    if (!message)
        return NULL;

    sendsize = sendMessage(message, size);
    if (sendsize != size) {
        throw NetworkException("fail to send message");
    }

    return recvMessage();
}
