#include <stdlib.h>
#include <string.h>

#include "CSGXECDSAQuote.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_ql_lib_common.h"
#include "sgx_ql_quote.h"
#include "sgx_ea_error.h"
#include "se_trace.h"

sgx_ea_status_t translateret(sgx_status_t err)
{
    sgx_ea_status_t earet;

    switch (err)
    {
        case SGX_SUCCESS:
            earet = SGX_EA_SUCCESS;
        break;

        default:
            earet = SGX_EA_ERROR_UNEXPECTED;
            break;
    }

    return earet;
}

CSGXECDSAQuote::CSGXECDSAQuote()
        : m_inited(false), m_pub_key_id_size(0), m_p_pub_key_id(NULL) {}

CSGXECDSAQuote::~CSGXECDSAQuote()
{
    if (m_pub_key_id_size)
        delete[] m_p_pub_key_id;
}

sgx_ea_status_t CSGXECDSAQuote::init_quote()
{
    uint32_t att_key_id_num, att_key_list_size;
    sgx_status_t ret;
    sgx_ql_att_key_id_list_t * attkeyidlist = NULL;
    sgx_att_key_id_t selected_key_id;

    if (m_inited)
        return SGX_EA_ERROR_ALREADY_INITIALIZED;

    ret = sgx_get_supported_att_key_id_num(&att_key_id_num);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_get_supported_att_key_id_num() return error code 0x%x\n", ret);
        return translateret(ret);
    }

    att_key_list_size = (uint32_t)sizeof(sgx_ql_att_key_id_list_t) + (uint32_t)sizeof(sgx_att_key_id_ext_t) * att_key_id_num;
    attkeyidlist = (sgx_ql_att_key_id_list_t *)new uint8_t[att_key_list_size];

    attkeyidlist->header.num_att_ids = att_key_id_num;

    ret = sgx_get_supported_att_key_ids(attkeyidlist->ext_id_list, att_key_id_num);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_get_supported_att_key_ids() return error code 0x%x\n", ret);
        delete attkeyidlist;
        return translateret(ret);
    }

    ret = sgx_select_att_key_id((uint8_t *)attkeyidlist, att_key_list_size, &selected_key_id);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_select_att_key_id() returns error code 0x%x, current platform doesn't support ECDSA quote.\n", ret);
        delete attkeyidlist;
        return translateret(ret);
    }
    else {
        SE_TRACE_NOTICE("sgx_select_att_key_id() return SUCCESS, current platform support ECDSA quote.\n");
    }

    ret = sgx_init_quote_ex(&selected_key_id, &m_qe_target_info, &m_pub_key_id_size, NULL);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_init_quote_ex() get size, return error code 0x%x.\n", ret);
        delete attkeyidlist;
        return translateret(ret);
    }

    m_p_pub_key_id = new uint8_t[m_pub_key_id_size];

    ret = sgx_init_quote_ex(&selected_key_id, &m_qe_target_info, &m_pub_key_id_size, m_p_pub_key_id);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_init_quote_ex() return error code 0x%x.\n", ret);
        delete attkeyidlist;
        delete[] m_p_pub_key_id;
        return translateret(ret);
    }

    m_selected_key_id = selected_key_id;

    m_inited = true;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CSGXECDSAQuote::get_qe_target_info(sgx_target_info_t *target)
{
    if (!target)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNINITIALIZED;

    *target = m_qe_target_info;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t CSGXECDSAQuote::get_quote_size(uint32_t * quotesize)
{
    uint32_t quote_size;
    sgx_status_t ret;

    if (!quotesize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNINITIALIZED;
    
    ret = sgx_get_quote_size_ex(&m_selected_key_id, &quote_size);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_get_quote_size_ex() return error code 0x%x.\n", ret);
        return translateret(ret);
    }

    *quotesize = quote_size;

    return SGX_EA_SUCCESS;
}

/*  Parameter Description:
 *     [in] uint8_t * app_report  - app_report should point to sgx_report_t
 *     [in, out] uint8_t * qe_report_info  - it points to a buffer sgx_qe_report_info_t, callee should set nonce and app enclave's target info when calling this function; SGX would output qe report to "qe_report" sub-field
 *     [out] uint8_t * quote - it points to quote output buffer, callee should allocate this buffer
 *     [in] quote_size - this is quote buffer's size
 * */
sgx_ea_status_t CSGXECDSAQuote::gen_quote(uint8_t * app_report, uint8_t * p_qe_report_info, uint8_t * quote, size_t quote_size)
{
    sgx_status_t ret;

    if (!app_report || !p_qe_report_info || !quote)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (!m_inited)
        return SGX_EA_ERROR_UNINITIALIZED;

    ret = sgx_get_quote_ex((sgx_report_t *)app_report, &m_selected_key_id, (sgx_qe_report_info_t *)p_qe_report_info, quote, (uint32_t)quote_size);
    if (ret != SGX_SUCCESS) {
        SE_TRACE_ERROR("sgx_get_quote_ex() return error code 0x%x.\n", ret);
        return translateret(ret);
    }

    return SGX_EA_SUCCESS;
}
