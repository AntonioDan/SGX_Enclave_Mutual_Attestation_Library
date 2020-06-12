#ifndef _SGX_UEA_KEY_EXCHANGE_INITIATOR_H_
#define _SGX_UEA_KEY_EXCHANGE_INITIATOR_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "sgx_tcrypto.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file 
 * @defgroup group_main sgx_uea_key_exchange_initiator.h 
 * This is enclave attestation initiator's main entry in untrusted runtime. 
 * It provides to functions to create ECDH secure session with responder. This library would load an initiator enclave inside, all ECDH operation would based on enclave.
 *
 * Generally, the secure session establish message flow is like this:
 *     Initiator                         responder
 *        |      <--- session id ---        |
 *        |   <--- msg1 (ga || Quote) ---   |
 *        |   --- msg2 (gb || Quote) --->   |
 *        |   <--- msg3 (Mac'ed resp) ---   |
 **/ 
class CEAServiceTranslator;

/**
 * This function initialize enclave attestation initiatior context. 
 * 
 * @param translator - This poinst to message serializer, it's typical work is to send message to responder and receive response message. E.g. if initiaor and responder runs in different machines in internet, you may implement this class with TCP socket.
 *
 * @return Status of this operation, one of below values
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_ALREADY_INITIALIZED
 *      - SGX_EA_ERROR_INIT_SESSION
 * 
 * Note: 
 *     1. this function must be called before calling other functions
 *     2. it's not allowed to re-initialize attestation context. If you have called this function successfully and try to re-call this function, this function would return SGX_EA_ERROR_ALREADY_INITIALIZED error.
 **/ 
sgx_ea_status_t sgx_uea_init_initiator_adv(std::shared_ptr<CEAServiceTranslator> tanslator);

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
sgx_ea_status_t sgx_uea_initiator_set_qeidentity(const char * qeidentityfilename);

/**
 * This function create ECDH secure session
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNINITIALIZED
 *      - SGX_EA_ERROR_NETWORK
 *      - SGX_EA_ERROR_LOAD_ENCLAVE
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_GEN_QUOTE
 *      - SGX_EA_ERROR_QE_IDENTITY
 *      - SGX_EA_ERROR_QVE_IDENTITY
 *      - SGX_EA_ERROR_UNEXPECTED
 *
 * Note: this function call load enclave to run as enclave attestation initiator role. The attestation responder role is transparent here and is hidden behind translator. The translator knows where is the attestation responder and how to communicate with it.
 **/ 
sgx_ea_status_t sgx_uea_initiator_create_ea_session();

#ifdef DEBUG
/**
 * This function is for debug purpose.
 * After establishing secure session, user can call this function to retrieve initiator session key.
 * This function should never be included or enabled in your product code!!!
 **/ 
sgx_ea_status_t sgx_uea_initiator_get_session_key(sgx_aes_gcm_128bit_key_t * key);

/**
 * This function is for debug purpose.
 * After establishing secure session, user can call this function to retrieve responder session key.
 * This function should never be included or enabled in your product code!!!
 **/ 
sgx_ea_status_t sgx_uea_initiator_query_server_session_key();
#endif

/**
 * This function sends {p_sentmsg, sendmsgsize} to responder through eastalished secure channel.
 * This function would encrypt the message content with AES-128-GCM, encode the message with BASE64, then sent to responder.
 * @param p_sentmsg - this points to message buffer to send.
 * @param sentmsgsize - this is messsage size.
 *
 * @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNINITIALIZED
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_CRYPTO
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_uea_initiator_sendmsg(const uint8_t * p_sentmsg, uint32_t sentmsgsize);

/**
 *  This function tries to receive message from responder. 
 * 
 *  @param pp_recvmsg - this points to received message from responder. 
 *  Note: this output message has been decrypted and processed by initiator enclave (libenclaveinitiator.so), which just decrypt the message with session sealing key to get the plain text. If you want to implement your data process logic, you need to modify enclaveinitiator project yourself.
 *  @param p_msgsize - this points to the message size 
 * 
 *  @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_INVALID_PARAMETER
 *      - SGX_EA_ERROR_NETWORK
 *      - SGX_EA_ERROR_UNEXPECTED  
 **/ 
sgx_ea_status_t sgx_uea_initiator_recvmsg(uint8_t **pp_msg, uint32_t *p_msgsize);

/**
 *  This function tries to close secure session.
 * 
 *  @return Status of this operation, one of below values:
 *      - SGX_EA_SUCCESS
 *      - SGX_EA_ERROR_UNINITIALIZED
 *      - SGX_EA_ERROR_UNEXPECTED
 **/ 
sgx_ea_status_t sgx_uea_initiator_close_ea_session();

#ifdef __cplusplus
}
#endif
#endif
