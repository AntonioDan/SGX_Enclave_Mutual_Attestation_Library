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
