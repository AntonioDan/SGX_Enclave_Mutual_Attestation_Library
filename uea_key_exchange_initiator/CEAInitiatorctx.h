#ifndef _CEAINITIATORCTX_H_
#define _CEAINITIATORCTX_H_

#include "sgx_ea.h"
#include "CEAInitiator.h"
#include "CEAException.h"
#include "CEAServiceTranslator.h"
#include "CEAServiceProvider.h"
#include "CSGXECDSAQuoteVerifier.h"
#include "CEAQEIdentity.h"
#include <memory>

class CEAInitiatorctx {
        enum {
            DEF_QE_ISVSVN_THRESHOLD = 5
        };

    public:
        CEAInitiatorctx(std::shared_ptr<CEAServiceTranslator> translator, std::shared_ptr<CSGXECDSAQuote> quote, 
                        std::shared_ptr<CSGXECDSAQuoteVerifier> quote_verifier, std::shared_ptr<CEAQEIdentity> qeidentity);
        ~CEAInitiatorctx();

    public:        
        void init();

        sgx_ea_status_t create_ea_session();
        sgx_ea_status_t get_msg1_content(sgx_ea_session_id_t sessionid, sgx_tea_msg1_content_t *p_msg1content);
        sgx_ea_status_t sendmsg2getmsg3content(sgx_ea_session_id_t sessionid, sgx_tea_msg2_content_t *p_msg2content, sgx_tea_msg3_content_t *p_msg3content);
        sgx_ea_status_t get_initiator_key(sgx_aes_gcm_128bit_key_t * key);
        sgx_ea_status_t get_responder_key();
        sgx_ea_status_t send_message(const uint8_t * p_msg, uint32_t size);
        sgx_ea_status_t recv_message(uint8_t **pp_msg, uint32_t *p_msgsize);

    public:
        sgx_ea_status_t init_qe_identity(const string& qeidentity);

    private:
        sgx_ea_status_t request_session_id(sgx_ea_session_id_t * p_sid);

    private:
        bool m_inited;
        std::shared_ptr<CEAInitiator> m_ea_initiator;
        std::shared_ptr<CEAServiceTranslator> m_translator;
        std::shared_ptr<CSGXECDSAQuote> m_quote;
        std::shared_ptr<CSGXECDSAQuoteVerifier> m_p_quote_verifier;
        std::shared_ptr<CEAQEIdentity> m_p_qeidentity;        
        sgx_ea_session_id_t m_sid;        

    private:
        CEAInitiatorctx(const CEAInitiatorctx&);
        CEAInitiatorctx& operator=(const CEAInitiatorctx&);
};

#endif
