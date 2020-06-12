/*************************************************************************
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
************************************************************************/

#include <stdio.h>
#include <string.h>
#include "CEAMsghandler.h"

#include "se_trace.h"
#include "sgx_urts.h"
#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "sgx_tcrypto.h"
#include "sgx_uea_key_exchange_responder.h"

#define ENCLAVE_RESPONDER "libenclaveresponder.signed.so"
#define QEIDENTITY_FILE   "qeidentity.json" 

CEAMsgHandler::CEAMsgHandler()
{}

sgx_ea_status_t CEAMsgHandler::init()
{    
    sgx_ea_status_t earet;

    earet = sgx_ea_init_responder();
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to initialize responder.\n");
        return earet;
    }

    earet = sgx_ea_responder_init_qeidentity(QEIDENTITY_FILE);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_WARNING("failed to init qe identity.\n");        
    }

#ifdef DEBUG
    sgx_ea_responder_show_qeidentity();
#endif

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAMsgHandler::procmsg0(ICommunicationSocket * socket)
{
    sgx_ea_status_t earet = SGX_EA_SUCCESS;
    sgx_uea_msg0_resp_t *p_msg0resp = NULL;

    if (!socket)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    earet = sgx_ea_responder_create_session(&p_msg0resp);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to create session.\n");
        return earet;
    }

    ssize_t writesize;

    writesize = socket->writeRaw((char *)p_msg0resp, sizeof(sgx_uea_msg0_resp_t));
    if (writesize != sizeof(sgx_uea_msg0_resp_t)) {
        earet = SGX_EA_ERROR_NETWORK;
    }

    return earet;
}

sgx_ea_status_t CEAMsgHandler::sendmsg1(ICommunicationSocket * socket, sgx_uea_msg1_req_t *msg1req)
{
    sgx_ea_status_t earet;
    sgx_uea_msg1_t *p_eamsg1 = NULL;
    uint32_t eamsg1size;
    
    if (!socket || !msg1req)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    earet = sgx_ea_responder_gen_msg1(msg1req->sessionid, &msg1req->nonce, &p_eamsg1, &eamsg1size);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    ssize_t writesize;
    writesize = socket->writeRaw((char *)p_eamsg1, eamsg1size);
    if (writesize != eamsg1size) {
        earet = SGX_EA_ERROR_NETWORK;
    }
    
    delete p_eamsg1;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAMsgHandler::procmsg2(ICommunicationSocket * socket, sgx_uea_msg2_t *msg2)
{
    sgx_ea_status_t earet;

    sgx_uea_msg3_t * p_msg3 = NULL;

    if (!socket || !msg2)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    earet = sgx_ea_responder_proc_msg2_gen_msg3(msg2->sessionid, msg2, &p_msg3);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("fail to generate message 3 in function %s.\n", __FUNCTION__);
        return earet;
    }

    ssize_t writesize, msg3size;
    sgx_ea_msg_header_t * p_ea_msg_header = (sgx_ea_msg_header_t *)p_msg3;
    msg3size = sizeof(sgx_ea_msg_header_t) + p_ea_msg_header->size;

    writesize = socket->writeRaw((char*)p_msg3, msg3size);
    if (writesize != msg3size) {
        earet = SGX_EA_ERROR_NETWORK;
    }
    
    delete p_msg3;

    return earet;
}

sgx_ea_status_t CEAMsgHandler::proc_sec_msg(ICommunicationSocket * socket, sgx_ea_msg_sec_t *p_sec_msg)
{
    sgx_ea_status_t earet;
    uint32_t rawmsgsize;
    uint8_t * p_plaintext = NULL;
    uint32_t plaintextsize;
	uint8_t messagebuf[256] = {0};

    rawmsgsize = p_sec_msg->header.size - (uint32_t)sizeof(sgx_ea_msg_header_t) - (uint32_t)sizeof(sgx_ea_session_id_t);

    earet = sgx_ea_responder_proc_msg(p_sec_msg->sessionid, (uint8_t *)&p_sec_msg->sec_msg, rawmsgsize,
                                        &p_plaintext, &plaintextsize);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to proc received message, earet is 0x%04x, %s, line %d.\n", earet, __FUNCTION__, __LINE__);
        return earet;
    }

	printf("Received message:\n");
	if (plaintextsize < 256) {
		memcpy(messagebuf, p_plaintext, plaintextsize);
		printf("%s\n", (char *)messagebuf);
	}
	/*
    int i;
    for (i = 0; i < plaintextsize; i++) {
        printf("0x%02x ", p_plaintext[i]);
    }
    printf("\n");*/

    uint8_t *p_encryptedmsg = NULL;
    uint32_t encryptedmsgsize;

    earet = sgx_ea_responder_encrypt_msg(p_sec_msg->sessionid, p_plaintext, plaintextsize,
                                                &p_encryptedmsg, &encryptedmsgsize);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to encrypt message, earet is 0x%04x, %s, line %d.\n", earet, __FUNCTION__, __LINE__);
        delete[] p_plaintext;
        return earet;
    }
   
    ssize_t writesize;

    writesize = socket->writeRaw((char*)p_encryptedmsg, encryptedmsgsize);
    if (writesize != encryptedmsgsize) {
        SE_TRACE_ERROR("failed to send secure message, earet is 0x%04x, %s, line %d.\n", earet, __FUNCTION__, __LINE__);
        earet = SGX_EA_ERROR_NETWORK;
    }

    delete[] p_encryptedmsg;    
    return earet;
}

sgx_ea_status_t CEAMsgHandler::proc_close_msg(sgx_ea_session_id_t sid)
{
	sgx_ea_status_t earet;

	earet = sgx_ea_responder_close_session(sid);
	if (earet != SGX_EA_SUCCESS) {
		SE_TRACE_ERROR("failed to close secure session.\n");
	} else {
		SE_TRACE_NOTICE("sesion %d closed.\n", (uint32_t)sid);
	}
	return SGX_EA_SUCCESS;
}

int CEAMsgHandler::procmsg(EAServerMsg * request)
{
    uint8_t * receivedmsg = NULL;
    sgx_ea_msg_header_t * msgheader = NULL;
    ICommunicationSocket * sock = NULL;
    uint8_t msgtype = 0;

    if (!request)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    receivedmsg = request->message;
    sock = request->socket;

    msgheader = (sgx_ea_msg_header_t *)receivedmsg;
    msgtype = msgheader->type;
    
    switch (msgtype)
    {
        case EA_MSG0:
        {
            int ret;

            ret = procmsg0(sock);
            if (ret != SGX_EA_SUCCESS)
                return ret;
        }
        break;

        case EA_MSG1_REQ:
        {
            int ret;

            ret = sendmsg1(sock, (sgx_uea_msg1_req_t *)receivedmsg);
            if (ret != SGX_EA_SUCCESS)
                return ret;
        }
        break;

        case EA_MSG2:
        {
            int ret;

            ret = procmsg2(sock, (sgx_uea_msg2_t *)receivedmsg);
            if (ret != SGX_EA_SUCCESS)
                return ret;
        }
        break;       

#ifdef DEBUG
        case EA_MSG_GET_MK:
        {
            sgx_ea_status_t ret;
            sgx_uea_get_mk_t *reqmsg;

            reqmsg = (sgx_uea_get_mk_t *)receivedmsg;

            ret = get_mk_by_sessionid(reqmsg->sessionid);
            if (ret != SGX_EA_SUCCESS) {
                return ret;
            }
        }
        break;
#endif

        case EA_MSG_SEC:
        {
            sgx_ea_status_t ret;
            sgx_ea_msg_sec_t *p_sec_msg;

            p_sec_msg = (sgx_ea_msg_sec_t *)receivedmsg;
            ret = proc_sec_msg(sock, p_sec_msg);
            if (ret != SGX_EA_SUCCESS)
                return ret;
        }
        break;

		case EA_MSG_CLOSE:
		{
			sgx_ea_status_t ret;
			sgx_ea_msg_close_t * p_close_msg;

			p_close_msg = (sgx_ea_msg_close_t *)receivedmsg;
			ret = proc_close_msg(p_close_msg->sessionid);
			if (ret != SGX_EA_SUCCESS) {
				return ret;
			}		
		}
		break;

    default:
        break;
    }

    return SGX_EA_SUCCESS;
}

#ifdef DEBUG
sgx_ea_status_t CEAMsgHandler::get_mk_by_sessionid(sgx_ea_session_id_t sessionid)
{
    sgx_ea_status_t earet;
    sgx_aes_gcm_128bit_key_t mk;

    earet = sgx_ea_responder_get_session_key(sessionid, &mk);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to retrieve session key.\n");
        return earet;
    }
    
    {
        uint8_t * pmk;

        printf("mk:\n");
        pmk = (uint8_t *)&mk;
        for (size_t i = 0; i < sizeof(mk); i++, pmk++) {
            printf("0x%02x ", *pmk);
        }

        printf("\n");

    }
    return SGX_EA_SUCCESS;
}
#endif

CEAMsgHandler * CEAMsgHandlerProvider::m_handler = NULL;

CEAMsgHandler * CEAMsgHandlerProvider::GetInstance()
{
    if (!m_handler) {
        sgx_ea_status_t ret;

        m_handler = new CEAMsgHandler;

        ret = m_handler->init();
        if (ret != SGX_EA_SUCCESS) {
            delete m_handler;
            m_handler =NULL;
            return NULL;
        }
    }

    return m_handler;
}
