#include <assert.h>
#include <stdio.h>
#include "se_trace.h"
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_attributes.h"

#include "CEAException.h"
#include "CEAResponder.h"
#include "enclaveresponder_u.h"

#define ENCLAVE_RESPONDER "libenclaveresponder.signed.so"

CEAResponder::CEAResponder() : m_inited(false), m_eid(0), 
                               m_role(SGX_EA_ROLE_RESPONDER), m_p_quote(NULL), m_p_qeidentity(NULL)
{}

CEAResponder::~CEAResponder()
{
}

sgx_ea_status_t CEAResponder::init()
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    ret = sgx_create_enclave(ENCLAVE_RESPONDER, 1, NULL, NULL, &m_eid, NULL);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_LOAD_ENCLAVE;

    m_p_quote = std::make_shared<CSGXECDSAQuote>();

    earet = m_p_quote->init_quote(); 
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to init quote in function %s, line %d\n", __FUNCTION__, __LINE__);
        sgx_destroy_enclave(m_eid);
        m_eid = 0;
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    m_p_quoteverifier = std::make_shared<CSGXECDSAQuoteVerifier>();

    m_inited = true;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::create_session(sgx_uea_msg0_resp_t **pp_msg)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_uea_msg0_resp_t *p_msg0resp = NULL;
    sgx_ea_session_id_t sessionid;
    
    assert(pp_msg != NULL);

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveresponder_sgx_ea_responder_init_session(m_eid, &earet, &sessionid);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS))
        return SGX_EA_ERROR_INIT_SESSION;

    p_msg0resp = new sgx_uea_msg0_resp_t;

    sgx_ea_init_msg_header(EA_MSG0_RESP, &p_msg0resp->header);
    p_msg0resp->header.size = sizeof(sgx_ea_session_id_t);
    p_msg0resp->sessionid = sessionid;

    *pp_msg = p_msg0resp;
    
    return SGX_EA_SUCCESS;

}

sgx_ea_status_t CEAResponder::gen_msg1(sgx_ea_session_id_t sid, sgx_ea_nonce_t * nonce, 
                                        sgx_uea_msg1_t ** pp_msg1, uint32_t * p_msg1size)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_target_info_t qe_target;
    sgx_tea_msg1_content_t msg1content;
    sgx_isv_svn_t latest_qe_isvsvn = DEF_QE_ISV_SVN_THRESHOLD;
    sgx_qe_report_info_t qereportinfo;

    assert((nonce != NULL) && (pp_msg1 != NULL) && (p_msg1size != NULL));

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    assert(m_p_quote != NULL);

    earet = m_p_quote->get_qe_target_info(&qe_target);
    if (earet != SGX_EA_SUCCESS)
        return SGX_EA_ERROR_GEN_MSG1;

    ret = enclaveresponder_sgx_ea_responder_gen_msg1_content(m_eid, &earet, sid, nonce, &qe_target, &msg1content);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to create message 1 in function %s, line %d, earet is 0x%x.\n", __FUNCTION__, __LINE__, earet);
        return SGX_EA_ERROR_GEN_MSG1;
    }

    memset((uint8_t*)&qereportinfo, 0, sizeof(sgx_qe_report_info_t));
    ret = enclaveresponder_sgx_tea_get_qe_report_info_withidx(m_eid, &earet, sid, &qereportinfo);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to generate qe report info.\n");
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    uint32_t quote_size;
    uint8_t * p_quote = NULL;

    earet = m_p_quote->get_quote_size(&quote_size);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to get quote size in function %s, line %d.\n", __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    p_quote = new uint8_t[quote_size];

    earet = m_p_quote->gen_quote((uint8_t *)&msg1content.report, (uint8_t*)&qereportinfo, p_quote, quote_size);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to get quote in function %s, line %d.\n", __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    // tbd: verify qe report
    earet = verify_qe_report(sid, &qereportinfo.qe_report, (uint8_t *)&qereportinfo.nonce, p_quote, quote_size, latest_qe_isvsvn);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to verify qe report %s, line %d.\n", __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    sgx_uea_msg1_t * msg1 = NULL;
    uint32_t msg1size = (uint32_t)sizeof(sgx_uea_msg1_t) + quote_size;
    msg1 = (sgx_uea_msg1_t *)new uint8_t[msg1size];

    sgx_ea_init_msg_header(EA_MSG1, &msg1->header);

    msg1->header.size = (uint32_t)sizeof(sgx_tea_msg1_content_t) + (uint32_t)sizeof(uint32_t) + quote_size;
    msg1->msgbody = msg1content;
    msg1->quote_size = quote_size;
    memcpy(msg1->quote, p_quote, quote_size);

    *pp_msg1 = msg1;
    *p_msg1size = msg1size;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::proc_msg2_get_msg3(sgx_ea_session_id_t sid, sgx_uea_msg2_t * p_msg2, sgx_uea_msg3_t ** pp_msg3)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_tea_msg3_content_t msg3content;
    sgx_qe_report_info_t qe_report_info;

    assert((p_msg2 != NULL) && (pp_msg3 != NULL));

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    /* verify ea message 2 */
    uint32_t supplemental_data_size;
    std::pair<uint32_t, sgx_ea_status_t> ret_pair = m_p_quoteverifier->get_quote_supplemental_data_size();
    if (ret_pair.second != SGX_EA_SUCCESS)         
        return SGX_EA_ERROR_GEN_QUOTE;

    supplemental_data_size = ret_pair.first;

    uint8_t * p_supplemental_data = NULL;
    p_supplemental_data = new uint8_t[supplemental_data_size];

    memset((uint8_t *)&qe_report_info, 0, sizeof(sgx_qe_report_info_t));
    ret = enclaveresponder_sgx_tea_get_qve_report_info(m_eid, &earet, &qe_report_info);
    if (ret != SGX_SUCCESS || earet != SGX_EA_SUCCESS)
        return SGX_EA_ERROR_VERIFY_QUOTE;

    time_t curtime;
    time(&curtime);

    sgx_ql_qv_result_t quote_verification_result;
    uint32_t collateral_expiration_status;

    earet = m_p_quoteverifier->qv_verify_quote(curtime, (sgx_ql_qe_report_info_t*)&qe_report_info, 
                                                p_msg2->quote, p_msg2->quote_size, 
                                                p_supplemental_data, supplemental_data_size, 
                                                collateral_expiration_status, quote_verification_result);
    if (earet != SGX_EA_SUCCESS) {        
        delete[] p_supplemental_data;
               
        return earet;
    }

    if (collateral_expiration_status) {
        SE_TRACE_WARNING("quote collaral expired!!\n");
    }
    
    switch (quote_verification_result) 
    {
        case SGX_QL_QV_RESULT_OK:
        {
            SE_TRACE_NOTICE("succeed to verify ecdsa quote.\n");
        }
        break;

    default:
        {
            SE_TRACE_ERROR("Quote is invalid, quote verification result is 0x%x.\n", quote_verification_result);
            delete[] p_supplemental_data;
            return SGX_EA_ERROR_VERIFY_QUOTE;
        }
        break;
    }
    
    ret = enclaveresponder_sgx_ea_verify_qve_result(m_eid, &earet, curtime, collateral_expiration_status, quote_verification_result,
                                                    &qe_report_info.nonce, p_msg2->quote, p_msg2->quote_size, &qe_report_info.qe_report,
                                                    p_supplemental_data, supplemental_data_size);
    if (ret != SGX_SUCCESS || earet != SGX_EA_SUCCESS) {
        SE_TRACE_WARNING("fail to verify QVE report, ecall return 0x%4x, function return 0x%4x.\n", ret, earet);
        delete[] p_supplemental_data;        
        return SGX_EA_ERROR_INVALID_REPORT;
    }

    // tbd: check supplemental data
    delete[] p_supplemental_data;        

    ret = enclaveresponder_sgx_ea_responder_gen_msg3_content(m_eid, &earet, sid, &p_msg2->msgbody, &msg3content);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("fail to generate message 3 in function %s, line %d, sid is 0x%x, earet is 0x%x.\n", __FUNCTION__, __LINE__, sid, earet);
        return SGX_EA_ERROR_GEN_MSG3;
    }

    sgx_uea_msg3_t * p_msg3 = NULL;
    p_msg3 = new sgx_uea_msg3_t;

    sgx_ea_init_msg_header(EA_MSG3, &p_msg3->header);
    p_msg3->header.size = sizeof(sgx_tea_msg3_content_t);
    memcpy((uint8_t *)&p_msg3->msgbody, (uint8_t *)&msg3content, sizeof(sgx_tea_msg3_content_t));
   
    *pp_msg3 = p_msg3;
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::get_session_key(sgx_ea_session_id_t sid, sgx_aes_gcm_128bit_key_t * key)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!m_inited)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = enclaveresponder_sgx_ea_responder_get_mk(m_eid, &earet, sid, key);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        return SGX_EA_ERROR_GET_KEY;
    }
        
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::init_qeidentity(const string& s_qeidentity)
{
    if (!m_p_qeidentity)
        m_p_qeidentity = std::make_shared<CEAQEIdentity>();

    m_p_qeidentity->parse(s_qeidentity);

    return SGX_EA_SUCCESS;
}

void CEAResponder::showQEIdentity() const
{   
    if (!m_p_qeidentity)
        return;

    sgx_measurement_t mrsigner = m_p_qeidentity->get_mr_signer();
    sgx_isv_svn_t isvsvn = m_p_qeidentity->get_isvsvn();
    sgx_attributes_t attributes = m_p_qeidentity->get_attributes();

    printf("QE mrsigner:\n");
    for (uint8_t i = 0; i < SGX_HASH_SIZE; i++)
    {
        printf("%02x", mrsigner.m[i]);
    }
    printf("\n");

    printf("QE isvsvn: %d.\n", (uint32_t)isvsvn);
    
    printf("QE attributes:\n");
    uint8_t * tmp = (uint8_t *)&attributes;
    for (uint8_t i = 0; i < sizeof(sgx_attributes_t) / sizeof(uint8_t); i++)
    {
        printf("%02x", *tmp++);

        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
}

sgx_ea_status_t CEAResponder::verify_qe_report(sgx_ea_session_id_t sid, sgx_report_t * report, uint8_t * nonce, 
                uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t latest_qe_isvsvn)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    if (!m_inited)
        return SGX_EA_ERROR_UNINITIALIZED;

    ret = enclaveresponder_sgx_tea_verify_qe_report_adv_withidx(m_eid, &earet, sid, report,
                    nonce, quote, quote_size, latest_qe_isvsvn);
    if ((ret != SGX_SUCCESS) || (earet != SGX_EA_SUCCESS)) {
        SE_TRACE_ERROR("failed to verify report, ecall return 0x%04x, function return 0x%04x.\n", ret, earet);
        return SGX_EA_ERROR_GEN_QUOTE;
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t *p_decrypted_msg_size)
{
    assert(encrypted_msg != NULL);
    assert(p_decrypted_msg_size != NULL);
    assert(encrypted_msg_size >= sizeof(sgx_tea_sec_msg_t));
    
    sgx_tea_sec_msg_t * p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    *p_decrypted_msg_size = p_sec_msg->aes_gcm_data.payload_size;
    
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::decrypt_ea_msg(sgx_ea_session_id_t sid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                        uint8_t *p_decrypted_msg, uint32_t decrypted_msg_size)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    assert(encrypted_msg != NULL);
    assert(p_decrypted_msg != NULL);

    ret = enclaveresponder_sgx_ea_responder_decrypt_msg(m_eid, &earet, sid, encrypted_msg, encrypted_msg_size,
                                                        p_decrypted_msg, decrypted_msg_size);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAResponder::decrypt_ea_msg(sgx_ea_session_id_t sid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint8_t ** pp_decrypted_msg, uint32_t * p_decrypted_msg_size)
{
    uint32_t payloadsize;
    sgx_ea_status_t earet;
    uint8_t * p_rawplaintxt = NULL;

    assert(encrypted_msg != NULL);
    assert(pp_decrypted_msg != NULL);
    assert(p_decrypted_msg_size != NULL);

    earet = get_decrypted_msg_size(encrypted_msg, encrypted_msg_size, &payloadsize);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    p_rawplaintxt = new uint8_t[payloadsize];

    earet = decrypt_ea_msg(sid, encrypted_msg, encrypted_msg_size, p_rawplaintxt, payloadsize);
    if (earet != SGX_EA_SUCCESS) {
        delete[] p_rawplaintxt;
        return earet;
    }

    *pp_decrypted_msg = p_rawplaintxt;
    *p_decrypted_msg_size = payloadsize;

    return earet;
}

sgx_ea_status_t CEAResponder::get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    assert(p_secmsgsize != NULL);
    
    ret = enclaveresponder_sgx_ea_responder_get_encrypted_msg_size(m_eid, &earet, rawmsgsize, p_secmsgsize);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("failed to get secure message size, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAResponder::encrypt_msg(sgx_ea_session_id_t sid, const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                    uint8_t * p_encrypted_msg, uint32_t encrypted_msg_size)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;

    assert(p_rawmsg != NULL);
    assert(p_encrypted_msg != NULL);

    ret = enclaveresponder_sgx_ea_responder_encrypt_msg(m_eid, &earet, sid, p_rawmsg, rawmsgsize, 
                                                            p_encrypted_msg, encrypted_msg_size);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("failed to encrypt message, ecall return 0x%04x, function return 0x%04x, %s, line %d.\n",
                            ret, earet, __FUNCTION__, __LINE__);    
        return SGX_EA_ERROR_ENCLAVE;
    }

    return earet;
}

sgx_ea_status_t CEAResponder::get_sec_msg(sgx_ea_session_id_t sid, const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                            uint8_t **pp_secmsg, uint32_t *p_secmsgsize)
{
    sgx_ea_status_t earet;
    uint32_t secmsgsize;

    assert(p_rawmsg != NULL);
    assert(pp_secmsg != NULL);
    assert(p_secmsgsize != NULL);
    
    earet = get_sec_msg_size(rawmsgsize, &secmsgsize);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    uint8_t *rawmsgbuf = NULL;
    sgx_ea_msg_header_t *p_msgheader;

    rawmsgbuf = new uint8_t[secmsgsize + sizeof(sgx_ea_msg_header_t) + sizeof(sgx_ea_session_id_t)];

    p_msgheader = (sgx_ea_msg_header_t *)rawmsgbuf;

    sgx_ea_init_msg_header(EA_MSG_SEC, p_msgheader);
    p_msgheader->size = (uint32_t)sizeof(sgx_ea_session_id_t) + secmsgsize;

    earet = encrypt_msg(sid, p_rawmsg, rawmsgsize, (uint8_t*)rawmsgbuf + sizeof(sgx_ea_msg_header_t) + sizeof(sgx_ea_session_id_t), secmsgsize);
    if (earet != SGX_EA_SUCCESS) {
        delete[] rawmsgbuf;
        return earet;
    }

    *pp_secmsg = rawmsgbuf;
    *p_secmsgsize = secmsgsize + (uint32_t)sizeof(sgx_ea_msg_header_t) + (uint32_t)sizeof(sgx_ea_session_id_t);

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAResponder::close_session(sgx_ea_session_id_t sid)
{
	sgx_status_t ret;
	sgx_ea_status_t earet;

	if (!m_inited)
		return SGX_EA_ERROR_UNINITIALIZED;

	ret = enclaveresponder_sgx_ea_responder_close_ea_session(m_eid, &earet, sid); 
	if (ret != SGX_SUCCESS) {
		SE_TRACE_ERROR("ecall return failure.\n");
		return SGX_EA_ERROR_ENCLAVE;
	}
	
	return earet;	
}

sgx_ea_status_t CEAResponder::uninit()
{
    if (!m_inited)
        return SGX_EA_ERROR_UNINITIALIZED;

    sgx_destroy_enclave(m_eid);
    m_eid = 0;

    m_inited = false;

    return SGX_EA_SUCCESS;
}

