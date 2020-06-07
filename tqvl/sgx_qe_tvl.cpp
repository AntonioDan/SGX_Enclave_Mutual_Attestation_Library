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

static sgx_quote_nonce_t m_tqvl_nonce_for_qe;

static std::map<uint32_t, sgx_quote_nonce_t *> mapQENonce;

sgx_ea_status_t sgx_tea_get_qe_report_info(sgx_qe_report_info_t * p_qe_report_info)
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

    m_tqvl_nonce_for_qe = nonce;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_tea_get_qe_report_info_withidx(uint32_t id, sgx_qe_report_info_t * report_info)
{
    sgx_quote_nonce_t nonce;
    sgx_target_info_t target;

    if (!report_info)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (mapQENonce.find(id) != mapQENonce.end())
        return SGX_EA_ERROR_UNEXPECTED;

    memset((uint8_t*)&nonce, 0xac, sizeof(sgx_quote_nonce_t));

    if (sgx_self_target(&target) != SGX_SUCCESS)
        return SGX_EA_ERROR_UNEXPECTED;

    report_info->nonce = nonce;
    report_info->app_enclave_target_info = target;
    
    sgx_quote_nonce_t * p_nonce = new sgx_quote_nonce_t;

    *p_nonce = nonce;

    mapQENonce.insert(std::map<uint32_t, sgx_quote_nonce_t *>::value_type(id, p_nonce));

    return SGX_EA_SUCCESS;
}

#define BREAK_IF_ERROR(x) \
    if ((x) != SGX_SUCCESS) break;

sgx_ea_status_t sgx_tea_verify_qe_report_adv_internal(sgx_report_t * qe_report, uint8_t * nonce, 
                                                const uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t qe_isvsvn_threshold)
{
    sgx_status_t ret;
    sgx_ea_status_t earet = SGX_EA_SUCCESS;
    sgx_sha_state_handle_t handle = NULL;

    if ((!nonce && quote)
        || (nonce && !quote))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!qe_report)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    ret = sgx_verify_report(qe_report);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_INVALID_REPORT;

    if ((qe_report->body.attributes.flags & SGX_FLAGS_DEBUG) != 0)
        return SGX_EA_ERROR_INVALID_REPORT;

    if (memcmp((uint8_t *)&m_qe_mrsigner, (uint8_t *)&qe_report->body.mr_signer, sizeof(sgx_measurement_t)) != 0)
        return SGX_EA_ERROR_INVALID_REPORT;

    if ((uint32_t)qe_report->body.isv_svn < (uint32_t)qe_isvsvn_threshold)
        return SGX_EA_ERROR_INVALID_REPORT;

    if (nonce)
    {
        do
        {
            sgx_sha256_hash_t hash;
    
            earet = SGX_EA_ERROR_CRYPTO;

            ret = sgx_sha256_init(&handle);
            BREAK_IF_ERROR(ret);

            ret = sgx_sha256_update(nonce, sizeof(sgx_quote_nonce_t), handle);
            BREAK_IF_ERROR(ret);

            ret = sgx_sha256_update(quote, quote_size, handle);
            BREAK_IF_ERROR(ret);

            ret = sgx_sha256_get_hash(handle, &hash);
            BREAK_IF_ERROR(ret);
        
            ret = sgx_sha256_close(handle);
            BREAK_IF_ERROR(ret);

            handle = NULL;

            if (memcmp((uint8_t *)&hash, qe_report->body.report_data.d, sizeof(sgx_sha256_hash_t)) != 0)
                return SGX_EA_ERROR_INVALID_REPORT;

            earet = SGX_EA_SUCCESS;

        } while (0);
    }

    if (handle)
        sgx_sha256_close(handle);

    return earet;
}

sgx_ea_status_t sgx_tea_verify_qe_report_adv(sgx_report_t * qe_report, uint8_t * nonce, 
                                                const uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t qe_isvsvn_threshold)
{
    sgx_ea_status_t earet;

    earet = sgx_tea_verify_qe_report_adv_internal(qe_report, nonce, quote, quote_size, qe_isvsvn_threshold);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    if (memcmp(nonce, &m_tqvl_nonce_for_qe, sizeof(sgx_quote_nonce_t)) != 0)
        return SGX_EA_ERROR_NONCE_MISMATCH;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_tea_verify_qe_report_adv_withidx(uint32_t id, sgx_report_t * qe_report, uint8_t * nonce, 
                                                const uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t qe_isvsvn_threshold)
{
    sgx_ea_status_t earet = SGX_EA_SUCCESS;

    earet = sgx_tea_verify_qe_report_adv_internal(qe_report, nonce, quote, quote_size, qe_isvsvn_threshold);
    if (earet != SGX_EA_SUCCESS)
        return earet;

    std::map<uint32_t, sgx_quote_nonce_t *>::iterator iter;

    iter = mapQENonce.find(id);
    if (iter == mapQENonce.end())
        return SGX_EA_ERROR_UNEXPECTED;

    sgx_quote_nonce_t * target_nonce = (*iter).second;

    if (memcmp(target_nonce, nonce, sizeof(sgx_quote_nonce_t)) != 0)
        earet = SGX_EA_ERROR_NONCE_MISMATCH;

    if (earet == SGX_EA_SUCCESS) 
    {
        delete[] target_nonce;
        mapQENonce.erase(iter);
    }

    return earet;
}
