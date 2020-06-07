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
#include <SocketTranslator.h>

//#include <IAEResponse.h>
//#include <ISerializer.h>
#include <ICommunicationSocket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sgx_ea.h"

SocketTranslator::SocketTranslator()
{
}

SocketTranslator::~SocketTranslator()
{
    /*
    if (mSocketFactory != NULL)
    {
        delete mSocketFactory;
        mSocketFactory = NULL;
    }
    if (mSerializer != NULL)
    {
        delete mSerializer;
        mSerializer = NULL;
    }
    */
}

uint8_t* SocketTranslator::receiveMessage(ICommunicationSocket* sock) 
{
    sgx_ea_msg_header_t * p_ea_msg_header = NULL;

    p_ea_msg_header = (sgx_ea_msg_header_t *)sock->readRaw(sizeof(sgx_ea_msg_header_t));

    if (!p_ea_msg_header)
        return NULL;

    uint8_t * p_ea_msg = NULL;

    if (p_ea_msg_header->size > 0) {
        uint8_t* p_content = (uint8_t *)sock->readRaw(p_ea_msg_header->size);
        
        uint32_t eamsgsize = (uint32_t)sizeof(sgx_ea_msg_header_t) + p_ea_msg_header->size;

        p_ea_msg = new uint8_t[eamsgsize];

        memcpy(p_ea_msg, (uint8_t *)p_ea_msg_header, sizeof(sgx_ea_msg_header_t));
        memcpy(p_ea_msg + sizeof(sgx_ea_msg_header_t), p_content, p_ea_msg_header->size);

        delete[] p_ea_msg_header;
        delete[] p_content;
    } else {
        p_ea_msg = (uint8_t *)p_ea_msg_header;
    }

    return p_ea_msg;
}

uint8_t* SocketTranslator::receiveRequest(ICommunicationSocket* sock) {
    if (!sock)
        return NULL;

    return receiveMessage(sock);
}
