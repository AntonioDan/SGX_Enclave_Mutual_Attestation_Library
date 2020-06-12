#ifndef _SGX_EA_H_
#define _SGX_EA_H_

#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "sgx_tseal.h"

#define SGX_EA_NONCE_SIZE 16
#define AES_128_CMAC_SIZE 16
#define AES_128_GCM_IV_SIZE 16
#define AES_128_GCM_AAD_SIZE 16
#define AES_128_GCM_MAC_SIZE 16

#define SGX_EA_VERSION   1

typedef enum {
    EA_MSG0 = 1,
    EA_MSG0_RESP,
    EA_MSG1_REQ,
    EA_MSG1,
    EA_MSG2,
    EA_MSG3,
    EA_MSG_SEC,
    EA_MSG_GET_MK,
    EA_MSG_CLOSE,
    EA_MSG_UNKNOWN
} sgx_ea_msg_type_t;

typedef enum {
    SGX_EA_ROLE_INITIATOR = 1,
    SGX_EA_ROLE_RESPONDER = 2
} sgx_ea_role_t;

typedef enum {
    SGX_EA_SESSION_UNUSED = 1,
    SGX_EA_SESSION_INITED,
    SGX_EA_SESSION_WAIT_FOR_MSG1,
    SGX_EA_SESSION_WAIT_FOR_MSG2,
    SGX_EA_SESSION_WAIT_FOR_MSG3,
    SGX_EA_SESSION_ESTABLISHED,
    SGX_EA_SESSION_UNEXPECTED,    
} sgx_ea_session_status_t;

#pragma pack(push,1)
typedef uint32_t sgx_ea_session_id_t;
#define SGX_EA_SESSION_INVALID_ID (sgx_ea_session_id_t)(-1)

typedef struct sgx_ea_nonce {
    uint8_t data[SGX_EA_NONCE_SIZE];
} sgx_ea_nonce_t;

typedef struct aes_128_cmac {
    uint8_t data[AES_128_CMAC_SIZE];
} aes_128_cmac_t;

typedef struct sgx_ea_msg_header {
    uint8_t version;
    uint8_t type;
    uint32_t size;
} sgx_ea_msg_header_t;

//EA MSG0 : Initiator -> Responder
typedef struct sgx_uea_msg0 {
    sgx_ea_msg_header_t header;
} sgx_uea_msg0_t;

typedef struct sgx_uea_msg0_resp {
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid;
} sgx_uea_msg0_resp_t;

typedef struct sgx_uea_msg1_req {
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid;
    sgx_ea_nonce_t nonce; // this nonce is generated inside initiator enclave and sent to untrusted part through OCALL interface.
} sgx_uea_msg1_req_t;;

// EA MSG1 : Responder -> Initiator
typedef struct sgx_tea_msg1_content {
    sgx_ea_nonce_t nonce; // this nonce is generated in initiator enclave, responder copies it into the nonce here
    sgx_ec256_public_t pubkey;
    sgx_report_t report; // report.data = SHA256(nonce || pubkey)
    //sgx_qe_report_info_t qe_report_info;
} sgx_tea_msg1_content_t;

typedef struct sgx_uea_msg1 {
    //<tbd>Quote with user_data as hash(pubkey)
    sgx_ea_msg_header_t header;   
    sgx_tea_msg1_content_t msgbody;
    uint32_t quote_size;
    uint8_t quote[0];
} sgx_uea_msg1_t;

typedef struct sgx_tea_msg2_content {
    sgx_ec256_public_t pubkey;
    sgx_report_t report; // use it to generate ECDSA Quote
    //sgx_qe_report_info_t qe_report_info;
} sgx_tea_msg2_content_t;

// EA MSG2 : Initiator -> Responder
typedef struct sgx_uea_msg2 {
    // <tdb> Quote with user data as hash(peer_pubkey || pubkey)
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid;
    sgx_tea_msg2_content_t msgbody;
    uint32_t quote_size;
    uint8_t quote[0];
} sgx_uea_msg2_t;

typedef struct sgx_tea_msg3_content {
    int result;
    aes_128_cmac_t mac;
} sgx_tea_msg3_content_t;

// EA MSG3 : Responder -> Initiator
typedef struct sgx_uea_msg3 {
    sgx_ea_msg_header_t header;
    sgx_tea_msg3_content_t msgbody;
} sgx_uea_msg3_t;

// GET MK for verification: Initiator -> Responder
typedef struct sgx_uea_get_mk {
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid;
} sgx_uea_get_mk_t;

typedef struct sgx_tea_sec_msg {    
    sgx_aes_gcm_data_t aes_gcm_data;
} sgx_tea_sec_msg_t;

// EA_MSG_SEC
typedef struct sgx_ea_message_sec {
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid; // if the message is from reponder to initiator, this field is empty
    sgx_tea_sec_msg_t sec_msg;
} sgx_ea_msg_sec_t;

// EA_MSG_CLOSE client -> responder
typedef struct sgx_ea_message_close {
    sgx_ea_msg_header_t header;
    sgx_ea_session_id_t sessionid;
} sgx_ea_msg_close_t;

typedef struct sgx_ea_message {
    uint32_t size;
    uint8_t msgbody[0];
} sgx_ea_raw_message_t; 

struct EARawMsg {
    uint32_t size;
    uint8_t * msgbody;

#ifdef __cplusplus
public:
    EARawMsg(uint32_t, uint8_t *);
    ~EARawMsg();
    EARawMsg(const EARawMsg &);
    EARawMsg& operator=(const EARawMsg &);
#endif 
};
#pragma pack(pop)

#ifdef __cplusplus
inline void sgx_ea_init_msg_header(uint8_t msgtype, sgx_ea_msg_header_t *header)
{
    if (!header)
        return;

    if ((msgtype >= EA_MSG0) && (msgtype < EA_MSG_UNKNOWN)) {
        header->version = SGX_EA_VERSION;
        header->type = msgtype;
        header->size = 0;
    }
}
#endif

#endif
