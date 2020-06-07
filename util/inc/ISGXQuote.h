#ifndef _ISGXQUOTE_H_
#define _ISGXQUOTE_H_

#include <stdint.h>
#include "sgx_ea_error.h"

class ISGXQuote {
    public:
        virtual ~ISGXQuote(){}
    public:
        virtual sgx_ea_status_t init_quote() = 0;
        virtual sgx_ea_status_t get_quote_size(uint32_t *) = 0;
        virtual sgx_ea_status_t gen_quote(uint8_t * app_report, uint8_t * qe_report_info, uint8_t * quote, size_t quote_size) = 0;
};
#endif
