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
#include <string.h>
#include <fstream>
#include <iostream>
#include <memory>
using namespace std;

#include "sgx_uea_key_exchange_initiator.h"
#include "sgx_uea_key_exchange_initiator_ocall.h"

#include "se_trace.h"
#include "CEAInitiatorctx.h"
#include "CEAException.h"
#include "CEAServiceTranslator.h"
#include "CEAServiceProvider.h"

std::shared_ptr<CEAInitiatorctx> m_initiator;

sgx_ea_status_t sgx_uea_init_initiator_adv(std::shared_ptr<CEAServiceTranslator> translator)
{
    if (m_initiator)
        return SGX_EA_ERROR_ALREADY_INITIALIZED;

    try
    {
        std::shared_ptr<CSGXECDSAQuote> quote = std::make_shared<CSGXECDSAQuote>();
        std::shared_ptr<CSGXECDSAQuoteVerifier> quote_verifier = std::make_shared<CSGXECDSAQuoteVerifier>();
        std::shared_ptr<CEAQEIdentity> qeidentity = std::make_shared<CEAQEIdentity>();

        m_initiator = std::make_shared<CEAInitiatorctx>(translator, quote, quote_verifier, qeidentity);

        m_initiator->init();
    }catch (...)
    {
        return SGX_EA_ERROR_INIT_SESSION;    
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_uea_initiator_create_ea_session()
{
    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try 
    {
        return m_initiator->create_ea_session();
    } catch (NetworkException& exception) {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

// this is for OCALL support
sgx_ea_status_t sgx_uea_initiator_get_msg1_content_ocall(sgx_ea_session_id_t sessionid, sgx_ea_nonce_t *p_nonce, sgx_tea_msg1_content_t *p_msg1content, sgx_report_body_t *p_responder_report_body)
{
    if (!p_nonce || !p_msg1content || !p_responder_report_body)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;
   
    try
    {
        return m_initiator->get_msg1_content(sessionid, p_nonce, p_msg1content, p_responder_report_body);
    } catch (NetworkException& exception) {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_uea_initiator_get_msg3_content_ocall(sgx_ea_session_id_t sessionid, sgx_tea_msg2_content_t *p_msg2content, sgx_tea_msg3_content_t *p_msg3content)
{   
    if (!p_msg2content || !p_msg3content)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;
    
    try 
    {
        return m_initiator->sendmsg2getmsg3content(sessionid, p_msg2content, p_msg3content);
    } catch (NetworkException& exception) {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

#ifdef DEBUG
sgx_ea_status_t sgx_uea_initiator_get_session_key(sgx_aes_gcm_128bit_key_t * key)
{
    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_initiator->get_initiator_key(key);
    } catch (NetworkException& exception) {
        return SGX_EA_ERROR_NETWORK;
    } catch (...)
    {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_uea_initiator_query_server_session_key()
{
    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_initiator->get_responder_key();
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}
#endif

/* This function initializes QE identity.
 * Input parameters:
 * const char * qeidentityfilename - this is qe identity file name
 * */
sgx_ea_status_t sgx_uea_initiator_set_qeidentity(const char * qeidentityfilename)
{
    string s_qeidentity;
    ifstream ifs;

    if (!qeidentityfilename)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        ifs.open(qeidentityfilename);
        ifs >> s_qeidentity;
        ifs.close();

        return m_initiator->init_qe_identity(s_qeidentity);
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

sgx_ea_status_t sgx_uea_initiator_sendmsg(const uint8_t * p_sentmsg, uint32_t sentmsgsize)
{
    if (!p_sentmsg)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_initiator->send_message(p_sentmsg, sentmsgsize);
    } catch (NetworkException&) {
        return SGX_EA_ERROR_NETWORK;
    } catch (...) {
        return SGX_EA_ERROR_UNEXPECTED;
    }
}

sgx_ea_status_t sgx_uea_initiator_recvmsg(uint8_t ** pp_recvmsg, uint32_t * p_msgsize)
{
    if (!pp_recvmsg || !p_msgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {        
        return m_initiator->recv_message(pp_recvmsg, p_msgsize);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return SGX_EA_ERROR_UNEXPECTED;        
    }
    
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_uea_initiator_close_ea_session()
{
    if (!m_initiator)
        return SGX_EA_ERROR_UNINITIALIZED;

    try
    {
        return m_initiator->close_ea_session();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return SGX_EA_ERROR_UNEXPECTED;
    }
        
    return SGX_EA_SUCCESS;
}
