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
#ifndef _CSGXECDSAQUOTEVERIFIER_H_
#define _CSGXECDSAQUOTEVERIFIER_H_

#include <utility>
#include "sgx_ql_lib_common.h"
#include "sgx_qve_header.h"
#include "sgx_ea.h"
#include "sgx_eid.h"

class CSGXECDSAQuoteVerifier
{
    public:
        std::pair<uint32_t, sgx_ea_status_t> get_quote_supplemental_data_size();

        sgx_ea_status_t qv_verify_quote(time_t expiration_check_time, sgx_ql_qe_report_info_t * qve_report_info, 
                                                            const uint8_t * p_quote, uint32_t quote_size, 
                                                            uint8_t * supplemental_data, uint32_t supplemental_data_size,
                                                            uint32_t &collateral_expiration_status, sgx_ql_qv_result_t &quote_verification_result);
};

#endif
