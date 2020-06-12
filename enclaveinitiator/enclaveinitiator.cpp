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
#include "sgx_trts.h"
#include "sgx_error.h"
#include "string.h"
#include "sgx_ea.h"
#include "sgx_tea_key_exchange_initiator.h"
#include "sgx_ea_error.h"

#include "enclaveinitiator_t.h"

#define RESPONDER_ISVSVN 0
#define RESPONDER_PRODID 0

typedef struct ea_session {
    bool m_inited;
    sgx_ea_session_id_t sessionid;
} ea_session_t;

ea_session_t m_ea_session = {false, 0};

sgx_ea_nonce_t m_nonce_for_responder = {0};

sgx_ea_status_t generate_quote_nonce_for_responder()
{
    if (sgx_read_rand((uint8_t *)&m_nonce_for_responder, sizeof(m_nonce_for_responder)) != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;
    
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t verify_responder_report(const sgx_report_body_t *report_body, const sgx_tea_msg1_content_t * p_tea_msg1)
{
    sgx_status_t ret;

    if (!report_body || !p_tea_msg1)
        return SGX_EA_ERROR_INVALID_PARAMETER;
    
    if (memcmp(&m_nonce_for_responder, &p_tea_msg1->nonce, sizeof(m_nonce_for_responder)) != 0)
        return SGX_EA_ERROR_NONCE_MISMATCH;
        
    // chech mac of report body, report data = SHA256(nonce || pubkey) 
    sgx_sha256_hash_t hash;
    do
    {
        sgx_sha_state_handle_t handler;

        ret = sgx_sha256_init(&handler);
        if (ret != SGX_SUCCESS)
            break;
        
        ret = sgx_sha256_update((uint8_t *)&p_tea_msg1->nonce, sizeof(sgx_quote_nonce_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }
        
        ret = sgx_sha256_update((uint8_t *)&p_tea_msg1->pubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_get_hash(handler, &hash);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        sgx_sha256_close(handler);
    } while (0);    

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    if (memcmp((uint8_t *)&hash, (uint8_t *)report_body->report_data.d, sizeof(sgx_sha256_hash_t)) != 0)
        return SGX_EA_ERROR_INVALID_REPORT;
    
    // check MRSIGNER, ISVSVN of responder enclave
    if ((report_body->isv_svn != (sgx_isv_svn_t)RESPONDER_ISVSVN)
        || (report_body->isv_prod_id != (sgx_prod_id_t)RESPONDER_PRODID))
        return SGX_EA_ERROR_INVALID_REPORT;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t ea_create_session(sgx_ea_session_id_t sid, sgx_target_info_t * p_qe_target)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_tea_msg1_content_t msg1content;
    sgx_tea_msg2_content_t msg2content;
    sgx_tea_msg3_content_t msg3content;
    sgx_report_body_t responder_report_body;

    if (!p_qe_target)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (m_ea_session.m_inited)
        return SGX_EA_ERROR_SESSION_ALREADY_ESTABLISHED;

    earet = sgx_ea_initiator_init_session(sid);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    earet = generate_quote_nonce_for_responder();
    if (earet != SGX_EA_SUCCESS) {
        sgx_ea_initiator_uninit_session();
        return earet;
    }       

    // OCALL to get msg1 from responder
    ret = sgx_uea_initiator_get_msg1_content_ocall(&earet, sid, &m_nonce_for_responder, &msg1content, &responder_report_body);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        sgx_ea_initiator_uninit_session();
        return SGX_EA_ERROR_GEN_MSG1;
    }        

    earet = verify_responder_report(&responder_report_body, &msg1content);
    if (earet != SGX_EA_SUCCESS) {
        sgx_ea_initiator_uninit_session();
        return earet;
    }        

    // generate msg2
    earet = sgx_ea_initiator_gen_msg2_content(&msg1content, p_qe_target, &msg2content);
    if (earet != SGX_EA_SUCCESS) {
        sgx_ea_initiator_uninit_session();
        return earet;
    }        

    // OCALL to get msg3 from responder
    ret = sgx_uea_initiator_get_msg3_content_ocall(&earet, sid, &msg2content, &msg3content);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        sgx_ea_initiator_uninit_session();
        return SGX_EA_ERROR_GEN_MSG3;
    }
    
    earet = sgx_ea_initiator_proc_msg3_content(&msg3content);
    if (earet != SGX_EA_SUCCESS) {
        sgx_ea_initiator_uninit_session();
        return earet;
    }        

    m_ea_session.sessionid = sid;
    m_ea_session.m_inited = true;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t ea_close_session()
{
    m_ea_session.sessionid = SGX_EA_SESSION_INVALID_ID;
    m_ea_session.m_inited = false;

    return sgx_tea_initiator_close_session();    
}
