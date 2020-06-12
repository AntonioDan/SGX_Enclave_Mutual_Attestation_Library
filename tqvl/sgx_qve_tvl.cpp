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
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "sgx_tqvl.h"
#include "time.h"
#include "string.h"
#include "sgx_ae_constants.h"

#include <map>

static sgx_quote_nonce_t m_tqvl_nonce_for_qve;

sgx_ea_status_t sgx_tea_get_qve_report_info(sgx_qe_report_info_t *p_qe_report_info)
{
    sgx_quote_nonce_t nonce;
    sgx_target_info_t target;

    if (!p_qe_report_info)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    memset((uint8_t*)&nonce, 0xac, sizeof(sgx_quote_nonce_t));

    if (sgx_self_target(&target) != SGX_SUCCESS)
        return SGX_EA_ERROR_UNEXPECTED;

    p_qe_report_info->nonce = nonce;
    p_qe_report_info->app_enclave_target_info = target;

    m_tqvl_nonce_for_qve = nonce;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_verify_qve_result(time_t expiration_time, uint32_t collateral_expiration_status, 
                                         uint32_t quote_verification_result, sgx_quote_nonce_t * p_nonce, 
                                         const uint8_t * p_quote, uint32_t quote_size, 
                                         sgx_report_t * qve_report, uint8_t * supplemental_data, uint32_t supplemental_data_size)
{
    sgx_status_t ret;
	sgx_ea_status_t earet = SGX_EA_SUCCESS;

	if (!qve_report || !p_nonce || !supplemental_data)
		return SGX_EA_ERROR_INVALID_PARAMETER;
	
	ret = sgx_verify_report(qve_report);
	if (ret != SGX_SUCCESS)
		return SGX_EA_ERROR_INVALID_REPORT;
	
	if ((uint16_t)qve_report->body.isv_svn < QVE_ISVSVN)
		return SGX_EA_ERROR_QVE_IDENTITY;

	if (qve_report->body.isv_prod_id != QVE_PROD_ID)
		return SGX_EA_ERROR_QVE_IDENTITY;

	if (memcmp(&qve_report->body.mr_signer, &m_qve_mrsigner, sizeof(sgx_measurement_t)) != 0)	
		return SGX_EA_ERROR_QVE_IDENTITY;

	if (memcmp(p_nonce, &m_tqvl_nonce_for_qve, sizeof(sgx_quote_nonce_t)) != 0)
		return SGX_EA_ERROR_NONCE_MISMATCH;

	do
	{	
		//report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00s)

		sgx_sha_state_handle_t handle;

		ret = sgx_sha256_init(&handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			break;
		}

		ret = sgx_sha256_update(p_nonce->rand, sizeof(p_nonce->rand), handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		ret = sgx_sha256_update(p_quote, quote_size, handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		ret = sgx_sha256_update((uint8_t *)&expiration_time, sizeof(expiration_time), handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		ret = sgx_sha256_update((uint8_t*)&collateral_expiration_status, sizeof(collateral_expiration_status), handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		ret = sgx_sha256_update((uint8_t*)&quote_verification_result, sizeof(quote_verification_result), handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		ret = sgx_sha256_update(supplemental_data, supplemental_data_size, handle);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		sgx_sha256_hash_t hash;

		ret = sgx_sha256_get_hash(handle, &hash);
		if (ret != SGX_SUCCESS) {
            earet = SGX_EA_ERROR_CRYPTO;
			sgx_sha256_close(handle);
			break;
		}

		if (memcmp((uint8_t *)&hash, (uint8_t *)qve_report->body.report_data.d, sizeof(sgx_sha256_hash_t)) != 0) {
            earet = SGX_EA_ERROR_MAC_MISMATCH;
			break;
		}
			
		sgx_sha256_close(handle);

	} while(0);
	
	return earet;
}
