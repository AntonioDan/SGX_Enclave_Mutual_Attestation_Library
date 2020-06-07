#ifndef _SGX_TQVL_H_
#define _SGX_TQVL_H_

#include "sgx_ea_error.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function generates qve report info, which is an input parameter when calling quote verification library interface.
 *
 * @param p_qe_report_info - this is output buffer of qve report info
 *
 * @return status code of this operation, one of
 *  - SGX_EA_SUCCESS
 *  - SGX_EA_ERROR_UNEXPECTED
 **/
sgx_ea_status_t sgx_tea_get_qve_report_info(sgx_qe_report_info_t *p_qe_report_info);

/**
 * This function verifies qve's quote verification result.
 *
 * @param expiration_time - this is the expiration time which is used by quote verification library to verify if quote verification collateral is expired or not. QvE would hash this field in report data, so this input must be the exact input when calling quote verification library interface.
 *
 * @param collateral_expiration_status - this is quote verification API's output, it indicates if quote verification collateral is expired with reference to given expiration check time. QvE would hash this field in report data, so this input must be the exact output of quote verification library interface.
 *
 * @param quote_verification_result - this is quote verification API's output, it indicates the quote verification result. QvE would hash this field in report data, so this input must be the exact output of quote verification library interface.
 *
 * @param p_nonce - this points to the nonce which is used by quote verification library to generate report. QvE would hash this field in report data, so this input must be the exact input when calling quote verification library inferface, it's a sub-field of sgx_qe_report_info_t.
 *
 * @param p_quote - this points to the quote which has been verified by Quote verification library. QvE would hash the {p_quote, quote_size} content to report data, so this pair of input must be the exact input when calling quote verification library interface.
 *
 * @param quote-size - this is quote size. See above description for p_quote.
 *
 * @param qve_report - this is the qve report output of Quote verification API.
 *
 * @param supplemental_data - this points to supplemental data output of quote verification API. QvE would hash {supplemental_data, supplemental_data_size to report data, so this pair of input must be the exact output of quote verifiction API.
 *
 * @param supplemental_data_size - this is supplemental data size. See above description for supplemental data.
 *
 * @return Status code of this operation, one of
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_INVALID_REPORT
 *      - SGX_EA_ERROR_MAC_MISMATCH
 *      - SGX_EA_ERROR_NONCE_MISMATCH
 *      - SGX_EA_ERROR_QVE_IDENTITY
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_UNEXPECTED
 */
sgx_ea_status_t sgx_ea_verify_qve_result(time_t expiration_time, uint32_t collateral_expiration_status, uint32_t quote_verification_result,
				                sgx_quote_nonce_t * p_nonce, const uint8_t * p_quote, uint32_t quote_size, 
                                sgx_report_t * qve_report, uint8_t * supplemental_data, uint32_t supplemental_data_size);

/**
 * This function generates qe report info. When generating ECDSA quote, we need to provide QE report info, with which QE would generate report.
 *
 * @param p_qe_report_info. This points to qe report info. output buffer.
 *
 * @return Status code of this operation, one of 
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_UNEXPECTED
 *
 * Note: When this function is called, we expect sgx_tea_verify_qe_report_adv() would be called in consequent flow. It's unexpected to call this API again before sgx_tea_verify_qe_report_adv() is called. 
 */
sgx_ea_status_t sgx_tea_get_qe_report_info(sgx_qe_report_info_t *p_qe_report_info);

/**
 * This function generates qe report info and maps it with input id. When generating ECDSA quote, we need to provide QE report info, with which QE would generate report. This function can be used when supporting multiple sessions, the id can be session id.
 *
 * @param id. This is session id input.
 * @param p_qe_report_info. This points to qe report info. output buffer.
 *
 * @return Status code of this operation, one of 
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_UNEXPECTED
 *
 * Note: When this function is called, we expect sgx_tea_verify_qe_report_adv_withidx() would be called in consequent flow. It's unexpected to call this API with same id input again before sgx_tea_verify_qe_report_adv_withidx() is called. 
 **/      
sgx_ea_status_t sgx_tea_get_qe_report_info_withidx(uint32_t id, sgx_qe_report_info_t * report_info);

/**
 * This function verifies qe report. Quote generation API would output QE report, user can calls this API to verify QE's identity. 
 *
 * @param qe_report. This points to qe report buffer, which is one output from Quote generation API.
 * @param nonce. This points to the nonce buffer which has been used to generate Quote. It's 16bytes size. QE would hash this buffer to report data. So this input must be the exact input of quote generation library.
 * @param quote. This points to the quote buffer which is output of quote generation library. QE would hash {quote, quote-size} content to report data. So this input must be the exact output of quote generation library.
 * @param quote_size. This is quote size. See above description for quote parameter.
 * @param qe_isvsvn_threshold. This is threshold of QE ISVSVN. With this input, user can tell to reject QE which has lower ISVSVN than this input.
 * 
 * @return Status code of this operation, one of 
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_INVALID_REPORT
 *      - SGX_EA_ERROR_MAC_MISMATCH
 *      - SGX_EA_ERROR_NONCE_MISMATCH
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_tea_verify_qe_report_adv(sgx_report_t * qe_report, uint8_t * nonce,
                                                const uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t qe_isvsvn_threshold);

/**
 * This function verifies qe report. Quote generation API would output QE report, user can calls this API to verify QE's identity. 
 *
 * @param qe_report. This points to qe report buffer, which is one output from Quote generation API.
 * @param nonce. This points to the nonce buffer which has been used to generate Quote. It's 16bytes size. QE would hash this buffer to report data. So this input must be the exact input of quote generation library.
 * @param quote. This points to the quote buffer which is output of quote generation library. QE would hash {quote, quote-size} content to report data. So this input must be the exact output of quote generation library.
 * @param quote_size. This is quote size. See above description for quote parameter.
 * @param qe_isvsvn_threshold. This is threshold of QE ISVSVN. With this input, user can tell to reject QE which has lower ISVSVN than this input.
 * 
 * @return Status code of this operation, one of 
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_INVALID_REPORT
 *      - SGX_EA_ERROR_MAC_MISMATCH
 *      - SGX_EA_ERROR_NONCE_MISMATCH
 *      - SGX_EA_ERROR_UNEXPECTED
 **/      
sgx_ea_status_t sgx_tea_verify_qe_report_adv_withidx(uint32_t id, sgx_report_t * qe_report, 
                                                    uint8_t * nonce, const uint8_t * quote, 
                                                    uint32_t quote_size, sgx_isv_svn_t qe_isvsvn_threshold);
#ifdef __cplusplus
}
#endif
#endif
