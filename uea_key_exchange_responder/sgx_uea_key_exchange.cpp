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
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
using namespace std;

#include "sgx_uea_key_exchange_responder.h"

#include "se_trace.h"
#include "CEAResponder.h"
#include "CEAException.h"
#include "CEAServiceTranslator.h"

std::shared_ptr<CEAResponder> m_ea_responder;

sgx_ea_status_t sgx_ea_init_responder()
{
    if (m_ea_responder)
        return SGX_EA_ERROR_ALREADY_INITIALIZED;

    try 
    {        
        m_ea_responder = std::make_shared<CEAResponder>();
     
        return m_ea_responder->init();     
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }

    return SGX_EA_SUCCESS;
}

/* This file is to set QEIdentity with file name.
 * Input parameter:
 * const char * qeidentityfile : this points to QEIdentity file name
 * */
sgx_ea_status_t sgx_ea_responder_init_qeidentity(const char * p_qeidentityfile)
{
    string s_qeidentity;
    ifstream ifs;

    if (!p_qeidentityfile)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    try 
    {
        ifs.open(p_qeidentityfile);
        ifs >> s_qeidentity;
        ifs.close();

        if (!m_ea_responder) 
            return SGX_EA_ERROR_UNINITIALIZED;

        return m_ea_responder->init_qeidentity(s_qeidentity);
    } catch (FormatException& obj) {
        cout << "receive FormatException" << endl;
        return SGX_EA_ERROR_PARSE_FILE;
    } catch (ios_base::failure&) {
        cout << "receive ios_base::failure" << endl;
        return SGX_EA_ERROR_FILE_ACCESS;
    } catch (...) {
        cout << "receive unknown exception" << endl;
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_ea_responder_create_session(sgx_uea_msg0_resp_t ** pp_msg)
{
    if (!pp_msg)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    try 
    {
        if (!m_ea_responder) 
            return SGX_EA_ERROR_UNINITIALIZED;

        return m_ea_responder->create_session(pp_msg);    
    } catch (SystemException&)
    {
        return SGX_EA_ERROR_SYSTEM;
    } catch (FormatException&)
    {
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    } catch (NetworkException&)
    {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_ea_responder_gen_msg1(sgx_ea_session_id_t sessionid, sgx_ea_nonce_t *nonce, 
                                            sgx_uea_msg1_t ** pp_msg1, uint32_t * p_msg1size)
{
    if (!nonce || !pp_msg1 || !p_msg1size)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_ea_responder) 
        return SGX_EA_ERROR_UNINITIALIZED;

    try 
    {
        return m_ea_responder->gen_msg1(sessionid, nonce, pp_msg1, p_msg1size);
    } catch (SystemException&)
    {
        return SGX_EA_ERROR_SYSTEM;
    } catch (FormatException&)
    {
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    } catch (NetworkException&)
    {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_ea_responder_proc_msg2_gen_msg3(sgx_ea_session_id_t sessionid, sgx_uea_msg2_t * p_msg2, sgx_uea_msg3_t ** pp_msg3)
{
    if (!p_msg2 || !pp_msg3)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_ea_responder) 
        return SGX_EA_ERROR_UNINITIALIZED;
    
    try 
    {
        return m_ea_responder->proc_msg2_get_msg3(sessionid, p_msg2, pp_msg3);
    } catch (SystemException&)
    {
        return SGX_EA_ERROR_SYSTEM;
    } catch (FormatException&)
    {
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    } catch (NetworkException&)
    {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

#ifdef DEBUG
sgx_ea_status_t sgx_ea_responder_get_session_key(sgx_ea_session_id_t sessionid, sgx_aes_gcm_128bit_key_t *key)
{
    if (!key)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_ea_responder) 
        return SGX_EA_ERROR_UNINITIALIZED;
    
    try 
    {
        return m_ea_responder->get_session_key(sessionid, key);
    } catch (SystemException&)
    {
        return SGX_EA_ERROR_SYSTEM;
    } catch (FormatException&)
    {
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    } catch (NetworkException&)
    {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}
#endif

void sgx_ea_responder_show_qeidentity()
{
    if (!m_ea_responder) 
        return;
    
    try 
    {
        m_ea_responder->showQEIdentity();
    } catch (...) {
        SE_TRACE_WARNING("meet unexpected exception when printing qe identity.\n");
        return;
    }
}

sgx_ea_status_t sgx_ea_responder_proc_msg(sgx_ea_session_id_t sid, const uint8_t * rawmsg, uint32_t msgsize,
                                            uint8_t **pp_decrypted_msg, uint32_t *p_msgsize)
{
    if (!rawmsg || !pp_decrypted_msg || !p_msgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;
    
    if (!m_ea_responder)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_ea_responder->decrypt_ea_msg(sid, rawmsg, msgsize, pp_decrypted_msg, p_msgsize);
    } catch (...) {
        SE_TRACE_WARNING("meet unexpected exception when processing received message.\n");
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_ea_responder_encrypt_msg(sgx_ea_session_id_t sid, const uint8_t * rawmsg, uint32_t msgsize,
                                                uint8_t **pp_encrypted_msg, uint32_t *p_encrypted_msgsize)
{
    if (!rawmsg || !pp_encrypted_msg || !p_encrypted_msgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_ea_responder)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_ea_responder->get_sec_msg(sid, rawmsg, msgsize, pp_encrypted_msg, p_encrypted_msgsize);
    }
    catch(const std::exception& e)
    {
        SE_TRACE_WARNING("meet unexpected exception when encrypting message.\n");
        std::cerr << e.what() << '\n';
        return SGX_EA_ERROR_UNEXPECTED;
    }    
}

sgx_ea_status_t sgx_ea_responder_close_session(sgx_ea_session_id_t sid)
{
	if (!m_ea_responder)
		return SGX_EA_ERROR_UNINITIALIZED;

	try
	{
		return m_ea_responder->close_session(sid);
	}
	catch (const std::exception& e)
	{
        SE_TRACE_WARNING("meet unexpected exception when encrypting message.\n");
        std::cerr << e.what() << '\n';
        return SGX_EA_ERROR_UNEXPECTED;
	}
	return SGX_EA_SUCCESS;
}
