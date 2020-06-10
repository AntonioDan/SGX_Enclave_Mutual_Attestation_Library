#include <assert.h>
#include <string.h>

#include "sgx_urts.h"
#include "se_trace.h"
#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "CEAInitiator.h"
#include "CSGXECDSAQuote.h"
#include "CEAException.h"
#include "enclaveinitiator_u.h"

#define ENCLAVE_INITIATOR "libenclaveinitiator.signed.so"

CEAInitiator::CEAInitiator() : m_inited(false), m_eid(0), m_role(SGX_EA_ROLE_INITIATOR) {}
CEAInitiator::~CEAInitiator(){}

sgx_ea_status_t CEAInitiator::init(sgx_target_info_t * qe_target_info)
{
    sgx_status_t ret;

    if (!qe_target_info)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    // load initiator enclave and init
    ret = sgx_create_enclave(ENCLAVE_INITIATOR, 1, NULL, NULL, &m_eid, NULL);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_LOAD_ENCLAVE;
    }    

    m_qe_target = *qe_target_info;
    m_inited = true;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::create_session(sgx_ea_session_id_t sid)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_ea_create_session(m_eid, &earet, sid, &m_qe_target);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to create session, ecall return 0x%04x, function return 0x%04x, %s, %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_INIT_SESSION;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::get_session_key(sgx_aes_gcm_128bit_key_t * key)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!key)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_sgx_ea_initiator_get_mk(m_eid, &earet, key);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to get session key, ecall return 0x%04x, function return 0x%04x, %s, %d",
                            ret, earet, __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_GET_KEY;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::uninit()
{
    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    sgx_destroy_enclave(m_eid);
    m_inited = false;
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::verify_qe_report(sgx_report_t * qereport, uint8_t * nonce, 
                                                uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t latest_qe_isvsvn)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!qereport || !nonce || !quote)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_sgx_tea_verify_qe_report_adv(m_eid, &earet, qereport, nonce, quote, quote_size, latest_qe_isvsvn);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to verify qe report, ecall return 0x%04x, function return 0x%04x, function %s, line %d.\n", ret, earet, __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::get_qve_reportinfo(sgx_qe_report_info_t * qereportinfo)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!qereportinfo)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_sgx_tea_get_qve_report_info(m_eid, &earet, qereportinfo);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to get qve report info, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_GEN_REPORT;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::get_qe_reportinfo(sgx_qe_report_info_t * qereportinfo)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!qereportinfo)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_sgx_tea_get_qe_report_info(m_eid, &earet, qereportinfo);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to get qve report info, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_GEN_REPORT;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::verify_qve_result(time_t expiration_time, uint32_t collateral_expiration_status, uint32_t quote_verification_result, sgx_quote_nonce_t * p_nonce, const uint8_t * p_quote, uint32_t quote_size, sgx_report_t * qve_report, uint8_t * supplemental_data, uint32_t supplemental_data_size)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!p_nonce || !p_quote || !qve_report || !supplemental_data)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveinitiator_sgx_ea_verify_qve_result(m_eid, &earet, expiration_time, collateral_expiration_status, quote_verification_result, p_nonce, p_quote, quote_size, qve_report, supplemental_data, supplemental_data_size);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("failed to verify qve result, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAInitiator::get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!p_secmsgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    ret = enclaveinitiator_sgx_tea_initiator_get_sec_msg_size(m_eid, &earet, rawmsgsize, p_secmsgsize);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("failed to get secure message size, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAInitiator::encrypt_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                    uint8_t * p_encrypted_msg, uint32_t encrypted_msg_size)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    ret = enclaveinitiator_sgx_tea_initiator_encrypt_msg(m_eid, &earet, p_rawmsg, rawmsgsize, 
                                                            p_encrypted_msg, encrypted_msg_size);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("failed to encrypt message, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAInitiator::get_sec_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                            uint8_t **pp_secmsg, uint32_t *p_secmsgsize)
{
    sgx_ea_status_t earet;
    uint32_t secmsgsize;

    if (!p_rawmsg || !pp_secmsg || !p_secmsgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    earet = get_sec_msg_size(rawmsgsize, &secmsgsize);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    uint8_t *rawmsgbuf = NULL;

    rawmsgbuf = new uint8_t[secmsgsize];

    earet = encrypt_msg(p_rawmsg, rawmsgsize, (uint8_t*)rawmsgbuf, secmsgsize);
    if (earet != SGX_EA_SUCCESS) {
        delete[] rawmsgbuf;
        return earet;
    }

    *pp_secmsg = rawmsgbuf;
    *p_secmsgsize = secmsgsize;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::get_plain_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size)
{
    if (!encrypted_msg || !p_decrypted_msg_size || (encrypted_msg_size < (uint32_t)sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_tea_sec_msg_t * p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    *p_decrypted_msg_size = p_sec_msg->aes_gcm_data.payload_size;
    
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiator::get_plain_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                            uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size)
{    
    sgx_status_t ret;
    sgx_ea_status_t earet;

    assert(encrypted_msg != NULL);
    assert(p_decrypted_msg != NULL);

    ret = enclaveinitiator_sgx_tea_initiator_decrypt_msg(m_eid, &earet, encrypted_msg, encrypted_msg_size,
                                                        p_decrypted_msg, decrypted_msg_size);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;    
}

sgx_ea_status_t CEAInitiator::get_plain_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                               uint8_t ** pp_decrypted_msg, uint32_t * p_decrypted_msg_size)
{
    sgx_ea_status_t earet;
    uint8_t *p_rawmsg = NULL;
    uint32_t decrypted_msg_size;

    assert(encrypted_msg != NULL);
    assert(pp_decrypted_msg != NULL);
    assert(p_decrypted_msg_size != NULL);

    earet = get_plain_msg_size(encrypted_msg, encrypted_msg_size, &decrypted_msg_size);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    p_rawmsg = new uint8_t[decrypted_msg_size];

    earet = get_plain_msg(encrypted_msg, encrypted_msg_size, p_rawmsg, decrypted_msg_size);
    if (earet != SGX_EA_SUCCESS) {
        delete[] p_rawmsg;
        return earet;
    }

    *pp_decrypted_msg = p_rawmsg;
    *p_decrypted_msg_size = decrypted_msg_size; 

    return SGX_EA_SUCCESS;
}
