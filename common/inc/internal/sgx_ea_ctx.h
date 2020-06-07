#ifndef _SGX_EA_CTX_H_
#define _SGX_EA_CTX_H_

#include "sgx_ea.h"
#include "sgx_tcrypto.h"

#define MK_ADDON "MK000000"
#define SK_ADDON "SK000000"

enum {
    SESSION_MK = 1,
    SESSION_SK
};

struct sgx_ea_initiator_context {
    sgx_ea_session_status_t status;
    sgx_ea_role_t role;
    sgx_ea_session_id_t sessionid;
    sgx_ec256_public_t peer_ecpubkey;
    sgx_ec256_public_t ecpubkey;
    sgx_ec256_private_t ecprivkey;
    sgx_ec256_dh_shared_t ecsharedkey;
    sgx_aes_gcm_128bit_key_t sk;
    sgx_aes_gcm_128bit_key_t mk;
    sgx_quote_nonce_t nonce_for_qe; // this is used to generate ECDSA Quote
} sgx_ea_initiator_context_t;

typedef struct sgx_ea_context {
    sgx_ea_session_status_t status;
    sgx_ea_role_t role;
    sgx_target_info_t qe_target;
    sgx_ea_session_id_t sessionid;
    sgx_ec256_public_t ecpubkey;
    sgx_ec256_private_t ecprivkey;
    sgx_ec256_dh_shared_t ecsharedkey;
    sgx_aes_gcm_128bit_key_t sk;
    sgx_aes_gcm_128bit_key_t mk;
    sgx_quote_nonce_t nonce_for_qe; // this is used to generate ECDSA Quote
} sgx_ea_context_t;

#endif
