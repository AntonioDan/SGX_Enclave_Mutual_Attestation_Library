#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sgx_tcrypto.h"
#include "CEAInitiatorctx.h"
#include "CEAQEIdentity.h"
#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "se_trace.h"

CEAInitiatorctx::CEAInitiatorctx(std::shared_ptr<CEAServiceTranslator> translator, std::shared_ptr<CSGXECDSAQuote> quote, std::shared_ptr<CSGXECDSAQuoteVerifier> quote_verifier, std::shared_ptr<CEAQEIdentity> qeidentity) 
        : m_status(SESSION_UNUSED), m_translator(translator), m_quote(quote), 
            m_p_quote_verifier(quote_verifier), m_p_qeidentity(qeidentity)
{
    m_ea_initiator = std::make_shared<CEAInitiator>();
}

CEAInitiatorctx::~CEAInitiatorctx()
{
}

void CEAInitiatorctx::init()
{
    if (m_status != SESSION_UNUSED)
        return;

    sgx_target_info_t qe_target;

    m_quote->init_quote();
    m_quote->get_qe_target_info(&qe_target);
    m_ea_initiator->init(&qe_target);
    m_translator->init();
    
    m_status = SESSION_INITED;
}

sgx_ea_status_t CEAInitiatorctx::request_session_id(sgx_ea_session_id_t * p_sid)
{
    sgx_uea_msg0_t eamsg0;

    if (!p_sid)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (m_status != SESSION_INITED)
        return SGX_EA_ERROR_UNINITIALIZED;

    sgx_ea_init_msg_header(EA_MSG0, &eamsg0.header);
    eamsg0.header.size = 0;

    uint8_t * rawmsg = NULL;

    rawmsg = m_translator->sendandrecv((uint8_t *)&eamsg0, sizeof(sgx_uea_msg0_t));
    if (!rawmsg) {
        SE_TRACE_ERROR("failed to send or receive message.\n");
        throw NetworkException("failed to send or receive message.");
    }

    sgx_uea_msg0_resp_t * p_ea_msg0resp = (sgx_uea_msg0_resp_t *)rawmsg;

    if (p_ea_msg0resp->header.size != sizeof(sgx_ea_session_id_t)) {
        SE_TRACE_ERROR("msg0 response message size mismatch.\n");
        delete rawmsg;
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    }

    //todo check header

    *p_sid = p_ea_msg0resp->sessionid;

    SE_TRACE_NOTICE("session id is 0x%x\n", *p_sid);

    m_sid = *p_sid;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::create_ea_session()
{
    sgx_ea_status_t earet; 

    if (m_status != SESSION_INITED)
        return SGX_EA_ERROR_UNINITIALIZED;

    sgx_ea_session_id_t sid;

    earet = request_session_id(&sid);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    earet = m_ea_initiator->create_session(sid);
	if (earet != SGX_EA_SUCCESS) {
		close_responder_session(sid);
		return earet;	
	}

	m_status = SESSION_ESTABLISHED;
	return SGX_EA_SUCCESS;	
}

sgx_ea_status_t CEAInitiatorctx::get_msg1_content(sgx_ea_session_id_t sessionid, sgx_tea_msg1_content_t *p_msg1content)
{
    sgx_ea_nonce_t nonce;
    sgx_ea_status_t earet;
    sgx_qe_report_info_t qvereportinfo;

    if (m_status != SESSION_INITED)
        return SGX_EA_ERROR_UNINITIALIZED;

    if (!p_msg1content)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    // <tbd> I feel this nonce should be generated and checked in trusted part
    for (uint32_t i = 0; i < sizeof(nonce)/sizeof(int); i++)
    {
        *(int *)((uint8_t *)nonce.data + sizeof(int) * i) = rand();
    }

    sgx_uea_msg1_req_t msg1req;

    sgx_ea_init_msg_header(EA_MSG1_REQ, &msg1req.header);
    msg1req.header.size = sizeof(sessionid) + sizeof(nonce);
    msg1req.sessionid = sessionid;
    msg1req.nonce = nonce;

    uint8_t * rawmsgresp = NULL;
    rawmsgresp = m_translator->sendandrecv((uint8_t *)&msg1req, sizeof(sgx_uea_msg1_req_t));
    if (!rawmsgresp) {
        SE_TRACE_NOTICE("failed to send or receive message in function %s, line %d.\n", __FUNCTION__, __LINE__);
        throw NetworkException("failed to send or receive message");
    }

    // to do check header
    sgx_uea_msg1_t *p_ea_msg1 = (sgx_uea_msg1_t *)rawmsgresp;

    if (p_ea_msg1->header.size < sizeof(sgx_uea_msg1_t)) {
        delete rawmsgresp;
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    }

    memset((uint8_t *)&qvereportinfo, 0, sizeof(sgx_qe_report_info_t));
    earet = m_ea_initiator->get_qve_reportinfo(&qvereportinfo);
    if (earet != SGX_EA_SUCCESS) {
        delete rawmsgresp;
        return earet;
    }

    uint32_t supplemental_data_size;
    std::pair<uint32_t, sgx_ea_status_t> ret_pair = m_p_quote_verifier->get_quote_supplemental_data_size();
    if (ret_pair.second != SGX_EA_SUCCESS) {
        delete rawmsgresp;
        return ret_pair.second;
    }

    supplemental_data_size = ret_pair.first;

    uint8_t * p_supplemental_data = NULL;
    p_supplemental_data = new uint8_t[supplemental_data_size];

    time_t curtime;
    time(&curtime);

    sgx_ql_qv_result_t quote_verification_result;
    uint32_t collateral_expiration_status;
    earet = m_p_quote_verifier->qv_verify_quote(curtime, (sgx_ql_qe_report_info_t*)&qvereportinfo, 
                                                p_ea_msg1->quote, p_ea_msg1->quote_size, 
                                                p_supplemental_data, supplemental_data_size,
                                                collateral_expiration_status, quote_verification_result);
    if (earet != SGX_EA_SUCCESS) {
        delete[] p_supplemental_data;
        delete rawmsgresp;

        return earet;
    }

    if (collateral_expiration_status) {
        SE_TRACE_WARNING("quote verification collateral expired.\n");
    }
    // tbd: check supplemental data

    switch (quote_verification_result) 
    {
        case SGX_QL_QV_RESULT_OK:
        {
            SE_TRACE_NOTICE("succeed to verify ecdsa quote.\n");
        }
        break;

    default:
        {
            SE_TRACE_ERROR("Quote is invalid, error code is 0x%x.\n", quote_verification_result);
            delete rawmsgresp;

            return SGX_EA_ERROR_VERIFY_QUOTE;
        }
        break;
    }

    earet = m_ea_initiator->verify_qve_result(curtime, collateral_expiration_status, quote_verification_result,
                                                    &qvereportinfo.nonce, p_ea_msg1->quote, p_ea_msg1->quote_size, &qvereportinfo.qe_report,
                                                    p_supplemental_data, supplemental_data_size);
    if (earet != SGX_EA_SUCCESS) {
        delete rawmsgresp;
        return earet;
    }

	// verify report embeded in Quote
	//
    memcpy((uint8_t *)p_msg1content, (uint8_t*)&p_ea_msg1->msgbody, sizeof(sgx_tea_msg1_content_t));

    delete[] p_supplemental_data;
    delete rawmsgresp;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::sendmsg2getmsg3content(sgx_ea_session_id_t sessionid, sgx_tea_msg2_content_t *p_msg2content, sgx_tea_msg3_content_t *p_msg3content)
{
    uint32_t quote_size;
    sgx_ea_status_t earet;
    sgx_isv_svn_t latest_qe_isvsvn = DEF_QE_ISVSVN_THRESHOLD;
    sgx_qe_report_info_t qereportinfo;

    if (m_status != SESSION_INITED)
        return SGX_EA_ERROR_UNINITIALIZED;

    earet = m_quote->get_quote_size(&quote_size);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to generate quote size in function %s, line %d.\n", __FUNCTION__, __LINE__);
        return earet;
    }

    uint8_t * p_quote;
    p_quote = new uint8_t[quote_size];

    // tbd: generate qe report info
    memset((uint8_t *)&qereportinfo, 0, sizeof(sgx_qe_report_info_t));
    earet = m_ea_initiator->get_qe_reportinfo(&qereportinfo);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to qe report info in function %s, line %d.\n", __FUNCTION__, __LINE__);
        delete[] p_quote;
        return earet;
    }
    
    earet = m_quote->gen_quote((uint8_t*)&p_msg2content->report, (uint8_t*)&qereportinfo, p_quote, quote_size);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to generate quote in function %s, line %d.\n", __FUNCTION__, __LINE__);
        return earet;
    }

    if (m_p_qeidentity) {
        latest_qe_isvsvn = m_p_qeidentity->get_isvsvn();
    }

    // ECALL to verify QE report
    earet = m_ea_initiator->verify_qe_report(&qereportinfo.qe_report, (uint8_t *)&qereportinfo.nonce, 
                                                p_quote, quote_size, latest_qe_isvsvn);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to verify qe report, function %s, line %d.\n", __FUNCTION__, __LINE__);
        return earet;
    }

    uint32_t msg2size;
    sgx_uea_msg2_t * p_msg2 = NULL;
    msg2size = (uint32_t)sizeof(sgx_uea_msg2_t) + quote_size;

    p_msg2 = (sgx_uea_msg2_t *)new uint8_t[msg2size];

    sgx_ea_init_msg_header(EA_MSG2, &p_msg2->header);
    p_msg2->header.size = (uint32_t)sizeof(sgx_ea_session_id_t) + (uint32_t)sizeof(sgx_tea_msg2_content_t) + (uint32_t)sizeof(uint32_t) + quote_size;
    p_msg2->sessionid = sessionid;
    p_msg2->msgbody = * p_msg2content;
    p_msg2->quote_size = quote_size;
    memcpy(p_msg2->quote, p_quote, quote_size);

    uint8_t *rawmsg3 = NULL;
    rawmsg3 = m_translator->sendandrecv((uint8_t *)p_msg2, msg2size);
    if (!rawmsg3) {
        delete[] p_msg2;
        SE_TRACE_ERROR("failed to recv message in function %s, line %d.\n", __FUNCTION__, __LINE__);
        throw NetworkException("failed to send or receive message");
    }

    delete[] p_msg2;
    p_msg2 = NULL;

    sgx_uea_msg3_t * p_eamsg3 = NULL;
    p_eamsg3 = (sgx_uea_msg3_t *)rawmsg3;

    // check msg3 size
    if (p_eamsg3->header.size != sizeof(sgx_tea_msg3_content_t)) {
        delete rawmsg3;
        SE_TRACE_ERROR("message 3 header is incorrect, in function %s, line %d.\n", __FUNCTION__, __LINE__);
        return SGX_EA_ERROR_MESSAGE_FORMAT;
    }

    memcpy((uint8_t *)p_msg3content, (uint8_t*)&p_eamsg3->msgbody, sizeof(sgx_tea_msg3_content_t));

    delete rawmsg3;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::get_initiator_key(sgx_aes_gcm_128bit_key_t * key)
{
    return m_ea_initiator->get_session_key(key);
}

sgx_ea_status_t CEAInitiatorctx::get_responder_key()
{
    sgx_uea_get_mk_t ea_msg_mk;

    sgx_ea_init_msg_header(EA_MSG_GET_MK, &ea_msg_mk.header);
    ea_msg_mk.header.size = sizeof(sgx_ea_session_id_t);
    ea_msg_mk.sessionid = m_sid;

    size_t sendsize;
    sendsize = m_translator->sendMessage((uint8_t *)&ea_msg_mk, sizeof(sgx_uea_get_mk_t));
    if (sendsize != sizeof(sgx_uea_get_mk_t)) {
        SE_TRACE_ERROR("failed to send message in function %s, line %d.\n", __FUNCTION__, __LINE__);
        throw NetworkException("failed to send or receive message");
    }

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::init_qe_identity(const string& qeidentity)
{
    if (!m_p_qeidentity)
        m_p_qeidentity = std::make_shared<CEAQEIdentity>();

    m_p_qeidentity->parse(qeidentity);

    return SGX_EA_SUCCESS;
}

/**
 * This function takes raw message {p_msg, size} input and send it to responder through secure session.
 * 
 * @param p_msg - this points to the raw message to be sent
 * @param size - the size of sent message
 * 
 * Note: this function would encrypt the raw message with session sealing key, wraps the decrypted message with sgx_ea_msg_sec_t format (see sgx_ea.h declaration) and send
 * 
 **/
sgx_ea_status_t CEAInitiatorctx::send_message(const uint8_t * p_msg, uint32_t size)
{    
    sgx_ea_status_t earet;
    uint8_t * p_sec_msg = NULL;
    uint32_t sec_msg_size;

    assert(p_msg != NULL);

    earet = m_ea_initiator->get_sec_msg(p_msg, size, &p_sec_msg, &sec_msg_size);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    uint8_t * rawmsg = NULL;
    uint32_t rawmsgsize = sec_msg_size + (uint32_t)sizeof(sgx_ea_msg_header_t) + (uint32_t)sizeof(sgx_ea_session_id_t);

    rawmsg = new uint8_t[rawmsgsize];

    sgx_ea_msg_sec_t * p_secmsg = (sgx_ea_msg_sec_t *)rawmsg;

    sgx_ea_init_msg_header(EA_MSG_SEC, &p_secmsg->header);
    p_secmsg->header.size = sec_msg_size + (uint32_t)sizeof(sgx_ea_session_id_t);
    p_secmsg->sessionid = m_sid;

    memcpy((uint8_t *)rawmsg + sizeof(sgx_ea_msg_header_t) + sizeof(sgx_ea_session_id_t), p_sec_msg, sec_msg_size);

    delete[] p_sec_msg;

    size_t sendsize;
    sendsize = m_translator->sendMessage((uint8_t *)rawmsg, rawmsgsize);
    if (sendsize != rawmsgsize) {
        SE_TRACE_ERROR("failed to send message in function %s, line %d.\n", __FUNCTION__, __LINE__);
        delete[] rawmsg;
        throw NetworkException("failed to send or receive message");
    }
    
    delete[] rawmsg;
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::recv_message(uint8_t **pp_msg, uint32_t *p_msgsize)
{    
    uint8_t * p_recvrawmsg = NULL;

    // receive message from responder. This raw message follows format definition in sgx_ea.h and starts with sgx_ea_msg_header_t blob.
    p_recvrawmsg = m_translator->recvMessage();
    if (!p_recvrawmsg)
        return SGX_EA_ERROR_NETWORK;

    // check message header
    sgx_ea_msg_header_t * msgheader = (sgx_ea_msg_header_t *)p_recvrawmsg;

    if ((msgheader->version != SGX_EA_VERSION)
        || (msgheader->type >= EA_MSG_UNKNOWN)
        || (msgheader->size <= (uint32_t)sizeof(sgx_ea_msg_header_t) + (uint32_t)sizeof(sgx_ea_session_id_t)))
        return SGX_EA_ERROR_MESSAGE_FORMAT;

    // do ecall to decrypt the message
    sgx_tea_sec_msg_t * p_sec_msg = (sgx_tea_sec_msg_t *)(p_recvrawmsg + 
                                                        (uint32_t)sizeof(sgx_ea_msg_header_t) + (uint32_t)sizeof(sgx_ea_session_id_t));
    uint32_t sec_msg_size = msgheader->size - (uint32_t)sizeof(sgx_ea_msg_header_t) - (uint32_t)sizeof(sgx_ea_session_id_t);
    
    return m_ea_initiator->get_plain_msg((uint8_t *)p_sec_msg, sec_msg_size, pp_msg, p_msgsize);    
}

sgx_ea_status_t CEAInitiatorctx::close_ea_session()
{
    sgx_ea_status_t earet;

	if (m_status != SESSION_ESTABLISHED)
		return SGX_EA_ERROR_UNEXPECTED;

    earet = m_ea_initiator->close_ea_session();
	if (earet != SGX_EA_SUCCESS) {
        return earet;
	}

	earet = close_responder_session(m_sid);
	if (earet != SGX_EA_SUCCESS) {
		return earet;
	}

	m_status = SESSION_INITED;

	return SGX_EA_SUCCESS;
}

sgx_ea_status_t CEAInitiatorctx::close_responder_session(sgx_ea_session_id_t sid)
{
    sgx_ea_msg_close_t ea_close_msg;

    sgx_ea_init_msg_header(EA_MSG_CLOSE, &ea_close_msg.header);
    ea_close_msg.header.size = sizeof(sgx_ea_session_id_t);
    ea_close_msg.sessionid = sid;

    size_t sendsize;
    sendsize = m_translator->sendMessage((uint8_t *)&ea_close_msg, sizeof(sgx_ea_msg_close_t));
    if (sendsize != sizeof(sgx_ea_msg_close_t)) {
        SE_TRACE_ERROR("failed to send message in function %s, line %d.\n", __FUNCTION__, __LINE__);        
        throw NetworkException("failed to send or receive message");
    }

    return SGX_EA_SUCCESS;
}
