#ifndef _SGX_UEA_KEY_EXCHANGE_RESPONDER_H_
#define _SGX_UEA_KEY_EXCHANGE_RESPONDER_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @defgroup group_main sgx_uea_key_exchange_responder.h
 * This is enclave attestation responder's main entry in untrusted runtime.
 * It provides to functions to create ECDH secure session with initiator. This library would load an initiator enclave inside, all ECDH operation would based on enclave.
 *
 * Generally, the secure session establish message flow is like this:
 *     Initiator                         responder
 *        |      <--- session id ---        |
 *        |   <--- msg1 (ga || Quote) ---   |
 *        |   --- msg2 (gb || Quote) --->   |
 *        |   <--- msg3 (Mac'ed resp) ---   |
 **/

/**
 * This function initialize enclave attestation responder context.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_ALREADY_INITIALIZED
 *      - SGX_EA_ERROR_UNEXPECTED
 *
 * Note: this function would load an enclave to run as enclave attesation responder role.
 * */
sgx_ea_status_t sgx_ea_init_responder();

/**
 * This function sets QE identity.
 * During enclave attestation, both initiator and responder would generate ECDSA quote as a method to attest to peer. It's assumed that initiator or responder needs to verify QE enclave's identity before sending quote to peer. Intel pubblishes SGX Quote enclave in internet, user request it from internet, read the content which is JSON format and input the Json string here.
 *
 * @param qeidentityfilename - this points to QE Identity file content string, which is JSON format.
 *
 * @return Status of this operation, one of below values
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_UNINITIALIZED
 *      - SGX_EA_ERROR_PARSE_FILE
 *      - SGX_EA_ERROR_UNEXPECTED
 **/
sgx_ea_status_t sgx_ea_responder_init_qeidentity(const char * qeidentityfile);

/**
 * This function wraps trusted interface to generate enclave attestation message 0 response.
 * The enclave attesation secure session start with initiator sending message 0 request to responder, which means intention to create secure session. Responder would respond messgae 0 response, which includes secure sesion id.
 *
 * @param p_msg0resp - this points to message 0 response output buffer.
 *
 * @return Status of this operation, one of below values
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_UNEXPECTED
 *      - SGX_EA_ERROR_SYSTEM
 *      - SGX_EA_ERROR_MESSAGE_FORMAT
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_responder_create_session(sgx_uea_msg0_resp_t ** p_msg0resp);

/**
 * This function wraps trusted interface to generate enclave attesation message 1
 *
 * @param sessionid - this is session id input.
 * @param nonce - this points to nonce input buffer. In remote attestation, responder usually sends a nonce to initiator, initiator needs to generate a quote with this nonce. Responder would authenticate the quote. We think ISV enclave needs to generate this nonce, so we provide this input parameter.
 * @pp_msg1 - this points to enclave attestation message 1 buffer. The buffer is allocated inside the function and p_msg1size points to message 1 size.
 * @p_msg1size - this points to message 1 buffer size, see above description.
 *
 * @return Status of this operation, one of below values
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_LOAD_ENCLAVE
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_GEN_REPORT
 *      - SGX_EA_ERROR_GEN_QUOTE
 *      - SGX_EA_ERROR_UNEXPECTED
 *      - SGX_EA_ERROR_SYSTEM
 **/
sgx_ea_status_t sgx_ea_responder_gen_msg1(sgx_ea_session_id_t sessionid, sgx_ea_nonce_t *nonce, 
                                            sgx_uea_msg1_t ** pp_msg1, uint32_t * p_msg1size);

/**
 * This function wraps trusted interface to process enclave attestation message 2 and generates message 3.
 *
 * @param sessionid - This is session id input.
 * @param p_msg2 - This points to enclave attestation message 2 input buffer.
 * @param pp_msg3 - This points to enclave attesation message 3 output buffer. The buffer is allocated inside this function.
 *
 * @return Status of this operation, one of below values
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_GEN_REPORT
 *      - SGX_EA_ERROR_GEN_QUOTE
 *      - SGX_EA_ERROR_INVALID_REPORT
 *      - SGX_EA_ERROR_VERIFY_QUOTE
 *      - SGX_EA_ERROR_NONCE_MISMATCH
 *      - SGX_EA_ERROR_MAC_MISMATCH
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_responder_proc_msg2_gen_msg3(sgx_ea_session_id_t sessionid, sgx_uea_msg2_t * p_msg2, sgx_uea_msg3_t ** pp_msg3);

sgx_ea_status_t sgx_ea_responder_get_session_key(sgx_ea_session_id_t sessionid, sgx_aes_gcm_128bit_key_t *key);

void sgx_ea_responder_show_qeidentity();

/**
 * This function wraps trusted interface to process secure message content received from initiator.
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
 **/ 
sgx_ea_status_t sgx_ea_responder_proc_msg(sgx_ea_session_id_t sid, const uint8_t * rawmsg, uint32_t msgsize,
                                            uint8_t **pp_decrypted_msg, uint32_t *p_msgsize);

/**
 * This function wrapps trusted interface to encrype message before sending to initiator
 * 
 * @param sessionid - This is session id input.
 * @param rawmsg - This points to input message buffer {rawmsg, msgsize}
 * @param msgsize - This is input message size
 * @param pp_encrypted_msg - This points to output message buffer. The message format is sgx_ea_msg_sec_t, see sgx_ea.h.
 * @param p_encrypted_msgsize - This points to output message buffer size
 * 
 * @return Status of the operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNEXPECTED
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO   
 **/ 
sgx_ea_status_t sgx_ea_responder_encrypt_msg(sgx_ea_session_id_t sid, const uint8_t * rawmsg, uint32_t msgsize,
                                                uint8_t **pp_encrypted_msg, uint32_t *p_encrypted_msgsize);

/**
 * This function close specified secure sesion.
 *
 * @param sid - This is secure session id.
 *
 * @return Status of this operation, one of below values:
 * 		- SGX_EA_SUCCESS
 *		- SGX_EA_ERROR_INVALID_PARAMETER
 *		- SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_ea_responder_close_session(sgx_ea_session_id_t sid);
#ifdef __cplusplus
}
#endif
#endif
