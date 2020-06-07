#ifndef _CSGXECDSAQUOTE_H_
#define _CSGXECDSAQUOTE_H_

#include "ISGXQuote.h"

#include "sgx_ql_lib_common.h"
#include "sgx_ql_quote.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_ea_error.h"

class CSGXECDSAQuote : public ISGXQuote {
    public:
        CSGXECDSAQuote();
        ~CSGXECDSAQuote();
    public:
        sgx_ea_status_t init_quote();
        sgx_ea_status_t get_qe_target_info(sgx_target_info_t *target);
        sgx_ea_status_t get_quote_size(uint32_t * quotesize);
        sgx_ea_status_t gen_quote(uint8_t * app_report, uint8_t * p_qe_report_info, uint8_t * quote, size_t quote_size);

    private:
        bool m_inited;
        size_t m_pub_key_id_size;
        uint8_t * m_p_pub_key_id;
        sgx_att_key_id_t m_selected_key_id;
        sgx_report_t m_qe_report;
        sgx_target_info_t m_qe_target_info;
};

#endif
