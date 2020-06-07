#include "sgx_ea_error.h"
#include "sgx_ql_lib_common.h"
#include "sgx_dcap_quoteverify.h"
#include "CSGXECDSAQuoteVerifier.h"
#include "se_trace.h"

std::pair<uint32_t, sgx_ea_status_t> CSGXECDSAQuoteVerifier::get_quote_supplemental_data_size()
{
    quote3_error_t ret;
    uint32_t supplemental_data_size;

    ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (ret != SGX_QL_SUCCESS)
        return std::make_pair(0, SGX_EA_ERROR_GET_QUOTE_SUPPLEMENTAL_DATA_SIZE);

    return std::make_pair(supplemental_data_size, SGX_EA_SUCCESS);
}

/* This function verify ECDSA Quote.
 * Input parameters:
 * sgx_ql_qe_report_info_t * qve_report_info. 
 *     This is an optional input. If user wants to use trusted QvE based quote verification, it needs to input this parameter. Otherwise, user can input nullptr for this parameter, in this case, it calls non-trusted QVL library to verify quote.
 * uint8_t * p_quote: 
 *     This points to quote buffer.
 * uint32_t quote_size.
 * 
 * uint8_t * supplemental_data:
 *     This is output buffer, this API would output Quote verification supplemental data here. This buffer is allocated by user.
 *
 * uint32_t supplemental_data_size.
 *
 * Return Value:
 * When it succeeds to verify Quote, it would return <quote_verification_result, SGX_EA_SUCESS>;
 * When it succeeds to verify Quote but quote verification collateral is expired, it would return <quote_verification_result, SGX_EA_ERROR_QUOTE_VERIFICATION_COLLATERAL_EXPIRED>
 * In other scenario, the second field of return pair includes the error code.
 * */

sgx_ea_status_t CSGXECDSAQuoteVerifier::qv_verify_quote(time_t expiration_check_time, sgx_ql_qe_report_info_t * qve_report_info, const uint8_t * p_quote, uint32_t quote_size, uint8_t * supplemental_data, uint32_t supplemental_data_size, uint32_t &collateral_expiration_status, sgx_ql_qv_result_t &quote_verification_result)
{
    quote3_error_t ret;
    //sgx_quote_nonce_t nonce;   

    if (!p_quote)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    ret = sgx_qv_verify_quote(p_quote, quote_size, 
                    NULL,
                    expiration_check_time,
                    &collateral_expiration_status,
                    &quote_verification_result,
                    qve_report_info,
                    supplemental_data_size,
                    supplemental_data);
    if (ret != SGX_QL_SUCCESS) {
        SE_TRACE_ERROR("fail to verify quote, ret code is 0x%x.\n", ret);
        return SGX_EA_ERROR_VERIFY_QUOTE;
    }   

    // tbd: verify qve report
    /*if (qve_report_info) {
        sgxret = enclaveresponder_sgx_ea_responder_verify_qve_result(eid, &earet, curtime, collateral_expiration_status, quote_verification_result, &qve_report_info->nonce, p_quote, quote_size, &qve_report_info->qe_report, supplemental_data, supplemental_data_size);
        if (sgxret != SGX_SUCCESS || earet != SGX_EA_SUCCESS)
            return std::make_pair(quote_verification_result, SGX_EA_ERROR_QVE_IDENTITY);
    }*/

    return SGX_EA_SUCCESS;
}
