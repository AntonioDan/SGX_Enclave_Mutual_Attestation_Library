#ifndef SGX_EA_KEY_EXCHANGE_U_H__
#define SGX_EA_KEY_EXCHANGE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_report.h"
#include "sgx_ea.h"
#include "sgx_ea_error.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t sgx_ea_init(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_role_t role);
sgx_status_t sgx_ea_initiator_init_session(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_session_id_t sessionid);
sgx_status_t sgx_ea_responder_init_session(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_session_id_t* sessionid);
sgx_status_t sgx_ea_responder_gen_msg1_content(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_session_id_t sessionid, sgx_ea_nonce_t* nonce, sgx_target_info_t* target, sgx_tea_msg1_content_t* p_msg1content);
sgx_status_t sgx_ea_responder_gen_msg3_content(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_session_id_t sessionid, sgx_tea_msg2_content_t* msg2, sgx_tea_msg3_content_t* msg3);
sgx_status_t sgx_ea_initiator_gen_msg2_content(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_tea_msg1_content_t* p_msg1content, sgx_target_info_t* p_qe_target, sgx_tea_msg2_content_t* msg2content);
sgx_status_t sgx_ea_initiator_proc_msg3_content(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_tea_msg3_content_t* msg3);
sgx_status_t sgx_ea_initiator_get_mk(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_aes_gcm_128bit_key_t* key);
sgx_status_t sgx_ea_responder_get_mk(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_ea_session_id_t sessionid, sgx_aes_gcm_128bit_key_t* key);
sgx_status_t sgx_ea_verify_qe_report(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_report_t* qe_report);
sgx_status_t sgx_ea_verify_qe_report_adv(sgx_enclave_id_t eid, sgx_ea_status_t* retval, sgx_report_t* qe_report, uint8_t* nonce, const uint8_t* quote, uint32_t quote_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
