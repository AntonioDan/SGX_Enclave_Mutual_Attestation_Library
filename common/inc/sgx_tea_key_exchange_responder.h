#ifndef _SGX_TEA_KEY_EXCHANGE_RESPONDER_H_
#define _SGX_tEA_KEY_EXCHANGE_RESPONDER_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @defgroup group_main sgx_tea_key_exchange_responder.h
 * This is the enclave attestation responder's main entry points in trusted runtime.
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
 * This function initiates secure session. This enclave attestation library supports one responder to create sessions with multiple initiators. When responder receives session establishment request from initiator, it would create this session context and assign a unique session id.
 *
 * @param sessionid - this points to session id output.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 **/ 
sgx_ea_status_t sgx_ea_responder_init_session(sgx_ea_session_id_t *sessionid);

/**
 * This function generate message 1 content for specified session.
 *
 * @param sessionid - this is session id input.
 * @param p_msg1content - this points to output buffer for message 1 content.
 *
 * Note: when untrusted runtime library receives message 1 content output, it would wrap it by attaching Quote part and send to initiator.
 **/ 
sgx_ea_status_t sgx_ea_responder_gen_msg1(sgx_ea_session_id_t sessionid, sgx_tea_msg1_content_t *p_msg1content);

/**
 * This function generates message content for specified session.
 *
 * @param sessionid - this is session id input.
 * @param nonce - this points to nonce input buffer. In remote attestation, responder usually sends a nonce to initiator, initiator needs to generate a quote with this nonce. Responder would authenticate the quote. We think ISV enclave needs to generate this nonce, so we provide this input parameter.
 * @param target - this points to QE enclave's target info input buffer. The message 1 includes ISV enclave's report with target for QE enclave, QE enclave would attest the report then geneate quote.
 * @p_msg1content - this points to message 1 content output buffer.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS 
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_GEN_REPORT
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_responder_gen_msg1_content(sgx_ea_session_id_t sessionid, const sgx_ea_nonce_t *nonce, const sgx_target_info_t * target, sgx_tea_msg1_content_t *p_msg1content);

/**
 * This function processes message 2 content and generates message 3 content. After responder processes message 2, it would generate message 3 to tell initiator session establishment result.
 * 
 * @param sessionid - this is session id input.
 * @param msg2 - this points to message 2 content input buffer
 * @param msg3 - this points to output buffer of message 3 content
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_MAC_MISMATCH
 *      - SGX_EA_ERROR_INVALID_REPORT
 *      - SGX_EA_ERROR_UNEXPECTED
 *
 * Note: when untrusted runtime library receive message 3 content, it would send it to initiator.
 **/ 
sgx_ea_status_t sgx_ea_responder_gen_msg3_content(sgx_ea_session_id_t sessionid, const sgx_tea_msg2_content_t * msg2, sgx_tea_msg3_content_t * msg3);

/**
 * This function is for debug purpose. After eastablishing secure session, user can call this function to get attestation responder's session key. This function should never be enabled in your product!!
 *
 * @param sessionid - This is session id input.
 * @param key - this points to output key buffer.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_GET_KEY
 **/ 
sgx_ea_status_t sgx_ea_responder_get_mk(sgx_ea_session_id_t sessionid, sgx_aes_gcm_128bit_key_t *key);

/**
 * This function decrypts secured message with session key. The {encrypted_msg, encrypted_msg_size} content is received from initiator, which encrypts the message with secure session's SK. When responder receives this message, it calls this function to decrypt the message with corresponding SK, which is indexed by session id.
 *
 * @param sessionid - This is session id input.
 * @param encypted_msg - This points to received message content from initiator.
 * @param encrypted_msg_size - This is encrypted message size.
 * @param p_decrypted_msg - This points to output decrypted message buffer. This buffer is allocted by caller, caller needs to get decrypted message size with sgx_ea_responder_get_decrypted_msg_size() API and allocates buffer accordingly.
 * @param decrypted_msg_size - This is decrypted message size.
 *
 * @return Status of the operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNEXPECTED
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *
 **/ 
sgx_ea_status_t sgx_ea_responder_decrypt_msg(sgx_ea_session_id_t sessionid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                                uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size);

/**
 * This function gets decrypted message size for the encrypted message input.
 *
 * @param encrypted_msg - this points to encrypted message buffer.
 * @param encrypted_msg_size - this is encrypted message size.
 * @param p_decrypted_msg_size - this points to decrypted message size
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_responder_get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size);

sgx_ea_status_t sgx_ea_responder_get_encrypted_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize);

sgx_ea_status_t sgx_ea_responder_encrypt_msg(sgx_ea_session_id_t sessionid, const uint8_t * p_rawmsgbuf, uint32_t rawmsgsize,
                                                uint8_t * p_secmsgbuf, uint32_t secmsgsize);
#ifdef __cplusplus
}
#endif
#endif
