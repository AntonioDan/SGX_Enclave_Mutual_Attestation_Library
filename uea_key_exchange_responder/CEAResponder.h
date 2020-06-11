#ifndef _CEA_RESPONDER_H_
#define _CEA_RESPONDER_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "sgx_urts.h"

#include "CSGXECDSAQuote.h"
#include "CSGXECDSAQuoteVerifier.h"
#include "CEAQEIdentity.h"
#include "sgx_tcrypto.h"

#include <memory>

class CEAResponder {
        enum {
            DEF_QE_ISV_SVN_THRESHOLD = 5,
        };
    public:
        CEAResponder();
        ~CEAResponder();

    public:
        sgx_ea_status_t init();
        sgx_ea_status_t create_session(sgx_uea_msg0_resp_t ** pp_msg);
        sgx_ea_status_t gen_msg1(sgx_ea_session_id_t sid, sgx_ea_nonce_t * nonce, 
                                    sgx_uea_msg1_t ** pp_msg1, uint32_t * p_msg1size);
        sgx_ea_status_t proc_msg2_get_msg3(sgx_ea_session_id_t sid, sgx_uea_msg2_t * p_msg2, sgx_uea_msg3_t ** pp_msg3);
        sgx_ea_status_t get_session_key(sgx_ea_session_id_t sid, sgx_aes_gcm_128bit_key_t * key);
        sgx_ea_status_t verify_qe_report(sgx_ea_session_id_t sid, sgx_report_t * qereport, uint8_t * nonce, uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t latest_qe_isvsvn = DEF_QE_ISV_SVN_THRESHOLD);
        sgx_ea_status_t decrypt_ea_msg(sgx_ea_session_id_t sid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint8_t ** pp_decrypted_msg, uint32_t * p_decrypted_msg_size);
        sgx_ea_status_t get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize);
        sgx_ea_status_t encrypt_msg(sgx_ea_session_id_t sid, const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                    uint8_t * p_encrypted_msg, uint32_t encrypted_msg_size);
        /**
         * This function wraps initiator enclave ECALL interface to encrypt the raw message input {p_rawmsg, rawmsgsize}.
         * 
         * @param sid - this is session id
         * @param p_rawmsg - this points to input message buffer
         * @param rawmsgsize - this is input message size
         * @param pp_secmsg - this points to output message buffer, the output message format is sgx_tea_sec_msg_t, see sgx_ea.h
         * @param p_secmsgsize - this points to output message buffer size.
         **/
        sgx_ea_status_t get_sec_msg(sgx_ea_session_id_t sid, const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                            uint8_t **pp_secmsg, uint32_t *p_secmsgsize);

		/**
		 * This function close secure session indexed by session id.
		 *
		 * @param sid - this is session id
		 **/ 
		sgx_ea_status_t close_session(sgx_ea_session_id_t sid);

        sgx_ea_status_t uninit();

    private:
        sgx_ea_status_t decrypt_ea_msg(sgx_ea_session_id_t sid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                        uint8_t *p_decrypted_msg, uint32_t decrypted_msg_size);
        sgx_ea_status_t get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t *p_decrypted_msg_size);

    public:
        sgx_ea_status_t init_qeidentity(const string & s_qeidentity);
        void showQEIdentity() const;
  
    private:
        bool m_inited;
        sgx_enclave_id_t m_eid;
        sgx_ea_role_t m_role;
        std::shared_ptr<CSGXECDSAQuote> m_p_quote;
        std::shared_ptr<CEAQEIdentity> m_p_qeidentity;
        std::shared_ptr<CSGXECDSAQuoteVerifier> m_p_quoteverifier;

    private:
        CEAResponder(const CEAResponder &);
        CEAResponder& operator=(const CEAResponder &);
};

#endif
