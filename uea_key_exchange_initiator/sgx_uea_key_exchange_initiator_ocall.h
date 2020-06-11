#ifndef _SGX_UEA_KEY_EXCHANGE_INITIATOR_OCALL_H_
#define _SGX_UEA_KEY_EXCHANGE_INITIATOR_OCALL_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"

#ifdef __cplusplus
extern "C" {
#endif

//OCALL stub
//sgx_ea_status_t sgx_ea_initiator_request_sessionid(sgx_ea_session_id_t *sid);
sgx_ea_status_t sgx_uea_initiator_get_msg1_content_ocall(sgx_ea_session_id_t sid, sgx_tea_msg1_content_t *p_msg1content);
sgx_ea_status_t sgx_uea_initiator_get_msg3_content_ocall(sgx_ea_session_id_t sid, sgx_tea_msg2_content_t * p_msg2content, sgx_tea_msg3_content_t * p_msg3content);
sgx_ea_status_t sgx_uea_initiator_close_session_ocall(sgx_ea_session_id_t sid);

#ifdef __cplusplus
}
#endif
#endif
