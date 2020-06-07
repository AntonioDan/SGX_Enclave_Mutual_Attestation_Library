#ifndef _CEA_INITIATOR_H_
#define _CEA_INITIATOR_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "CSGXECDSAQuote.h"
#include "CEAServiceTranslator.h"
#include "sgx_urts.h"

class CEAInitiator {
    public:        
        CEAInitiator();
        ~CEAInitiator();
        
    public:
        sgx_ea_status_t init(sgx_target_info_t * p_qe_target);
        sgx_ea_status_t create_session(sgx_ea_session_id_t sid);
        sgx_ea_status_t get_session_key(sgx_aes_gcm_128bit_key_t * key);        
        sgx_ea_status_t verify_qe_report(sgx_report_t * qereport, uint8_t * nonce, uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t latest_qe_isvsvn = 4);
        sgx_ea_status_t get_qve_reportinfo(sgx_qe_report_info_t * qereportinfo);
        sgx_ea_status_t get_qe_reportinfo(sgx_qe_report_info_t * qereportinfo);
        sgx_ea_status_t verify_qve_result(time_t expiration_time, uint32_t collateral_expiration_status, uint32_t quote_verification_result, sgx_quote_nonce_t * p_nonce, const uint8_t * p_quote, uint32_t quote_size, sgx_report_t * qve_report, uint8_t * supplemental_data, uint32_t supplemental_data_size);
        sgx_ea_status_t get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize);
        sgx_ea_status_t encrypt_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                    uint8_t * p_encrypted_msg, uint32_t encrypted_msg_size);
        sgx_ea_status_t get_sec_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                            uint8_t **pp_secmsg, uint32_t *p_secmsgsize);
        sgx_ea_status_t uninit();

    private:
        bool m_inited;
        sgx_enclave_id_t m_eid;
        sgx_ea_role_t m_role;
        sgx_target_info_t m_qe_target;
        
    private:
        CEAInitiator(const CEAInitiator&);
        CEAInitiator& operator=(const CEAInitiator&);   
};

#endif
