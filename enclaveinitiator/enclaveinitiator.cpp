#include "sgx_ea.h"
#include "sgx_tea_key_exchange_initiator.h"
#include "sgx_ea_error.h"

#include "enclaveinitiator_t.h"

typedef struct ea_session {
    bool m_inited;
    sgx_ea_session_id_t sessionid;
} ea_session_t;

ea_session_t m_ea_session = {false, 0};

sgx_ea_status_t ea_create_session(sgx_ea_session_id_t sid, sgx_target_info_t * p_qe_target)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_tea_msg1_content_t msg1content;
    sgx_tea_msg2_content_t msg2content;
    sgx_tea_msg3_content_t msg3content;

    if (!p_qe_target)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (m_ea_session.m_inited)
        return SGX_EA_ERROR_SESSION_ALREADY_ESTABLISHED;

    earet = sgx_ea_initiator_init_session(sid);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    // OCALL to get msg1 from responder
    ret = sgx_uea_initiator_get_msg1_content_ocall(&earet, sid, &msg1content);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS))
        return SGX_EA_ERROR_GEN_MSG1;

    // generate msg2
    earet = sgx_ea_initiator_gen_msg2_content(&msg1content, p_qe_target, &msg2content);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    // OCALL to get msg3 from responder
    ret = sgx_uea_initiator_get_msg3_content_ocall(&earet, sid, &msg2content, &msg3content);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        return SGX_EA_ERROR_GEN_MSG3;
    }
    
    earet = sgx_ea_initiator_proc_msg3_content(&msg3content);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    m_ea_session.sessionid = sid;
    m_ea_session.m_inited = true;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t ea_close_session()
{
    m_ea_session.sessionid = 0;
    m_ea_session.m_inited = false;

    return sgx_tea_initiator_close_session();    
}
