#ifndef _SGX_TEA_KEY_EXCHANGE_INITIATOR_H_
#define _SGX_TEA_KEY_EXCHANGE_INITIATOR_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @defgroup group_main sgx_tea_key_exchange_initiator.h
 * This is the enclave attestation initiator's main entry points in trusted runtime.
 * It provides functions to create ECDH secure session as initiator role.
 *
 * Note: This enclave attestation library doesn't support one initiator to create sessions with multiple responders. It supports one responder to create sessions with multiple initiators. Responder would assign a unique session id to each session. Before initiator creates secure session with reponder, it needs to request a session id from responder.
 *
 * Generally, the secure session establish message flow is like this:
 *     Initiator                         responder
 *        |      <--- session id ---        |
 *        |   <--- msg1 (ga || Quote) ---   |
 *        |   --- msg2 (gb || Quote) --->   |
 *        |   <--- msg3 (Mac'ed resp) ---   |
 **/ 

/**
 * This function initiates secure session's context for session id.
 *
 * @param sessionid - This is session id input. enclave attestation initiator needs to request a session id from responder and use it create secure session.
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_initiator_init_session(sgx_ea_session_id_t sessionid);

/**
 * This function processes msg1 content and generates msg2 content
 *
 * @param msg1 - This is pointer to message 1 content buffer. Message 1 is generated by attestaton responder.
 * @param p_qe_target - This is pointer to qe report info. This function outputs message 2 content, untrusted enclave attestation library would generate Quote for message 2 content, in this process, it needs qe report info. input. So we designed this output parameter. This parameter is obsolete.
 * @param msg2 - This points to output buffer of msg2 content.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_GEN_REPORT
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_UNEXPECTED
 *
 * Note: this function processes message 1 content in trusted context and generate message 2 content; untrusted runtime library would wrap message 2 content by attaching Quote part, it thens send message 2 to attestation responder.
 **/ 
sgx_ea_status_t sgx_ea_initiator_gen_msg2_content(sgx_tea_msg1_content_t * msg1, sgx_target_info_t* p_qe_target, sgx_tea_msg2_content_t * msg2);

/**
 * This function processes message 3, which is generated by attestation responder. After attesation initiator sends message 2 to responder, it waits for message 3 from responder; it extracts the content and call this function to process it.
 *
 * @param p_msg3content - This points to message 3 content.
 *
 * @return Satus of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_GEN_REPORT
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_initiator_proc_msg3_content(sgx_tea_msg3_content_t *p_msg3content);

/**
 * This is a debug stub function. After secure session is done, user can call this function to readout session key for debug purpose. You should never enable this function in your product!!
 *
 * @param key - This points to session key output buffer.
 **/ 
sgx_ea_status_t sgx_ea_initiator_get_mk(sgx_aes_gcm_128bit_key_t * key);

sgx_ea_status_t sgx_tea_initiator_get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize);

sgx_ea_status_t sgx_tea_initiator_encrypt_msg(const uint8_t * p_rawmsgbuf, uint32_t rawmsgsize,
                                                uint8_t * p_secmsgbuf, uint32_t secmsgsize);

sgx_ea_status_t sgx_tea_initiator_get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size);

sgx_ea_status_t sgx_tea_initiator_decrypt_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                               uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size);

#ifdef __cplusplus
}
#endif
#endif
