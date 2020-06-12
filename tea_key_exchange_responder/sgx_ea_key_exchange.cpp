#include "sgx_tcrypto.h"
#include "sgx_ea.h"
#include "sgx_tea_key_exchange_responder.h"
#include "sgx_ea_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_spinlock.h"
#include "sgx_trts.h"
#include "sgx_ea_ctx.h"
#include "sgx_ae_constants.h"

#include <vector>

static sgx_spinlock_t m_ea_db_lock = SGX_SPINLOCK_INITIALIZER;
static std::vector<sgx_ea_context_t *> m_ea_responder_ctx_vec;

static sgx_ea_session_id_t gen_session_id()
{
    static uint32_t session_seed = 0x100;
    return reinterpret_cast<sgx_ea_session_id_t>(session_seed++);
}

static sgx_ea_context_t * find_ea_session(sgx_ea_session_id_t sessionid)
{    
    auto iter = std::find_if(m_ea_responder_ctx_vec.begin(), m_ea_responder_ctx_vec.end(), [&](const sgx_ea_context_t * obj){
        return (obj->sessionid == sessionid);
    });

    return (iter == m_ea_responder_ctx_vec.end()) ? NULL : *iter;    
}

static void close_ea_session(sgx_ea_session_id_t sessionid)
{
    auto iter = std::find_if(m_ea_responder_ctx_vec.begin(), m_ea_responder_ctx_vec.end(), [&](const sgx_ea_context_t * obj){
        return (obj->sessionid == sessionid);
    });

	if (iter != m_ea_responder_ctx_vec.end()) {
		m_ea_responder_ctx_vec.erase(iter);
		free(*iter);
	}

	return;
}

sgx_ea_status_t derivekey(uint8_t keytype, const sgx_ec256_dh_shared_t *dhkey, sgx_cmac_128bit_tag_t * outputkey)
{
    sgx_status_t ret;
    sgx_sha256_hash_t hash;
    sgx_cmac_128bit_tag_t mac;
    uint8_t addon[8] = {0};

#define MK_ADDON "MK000000"
#define SK_ADDON "SK000000"

    switch (keytype)
    {
        case SESSION_MK:
        {
            memcpy(addon, MK_ADDON, sizeof(addon));
        }
        break;

        case SESSION_SK:
        {
            memcpy(addon, SK_ADDON, sizeof(addon));
        }
        break;

        default:
        {
            return SGX_EA_ERROR_INVALID_PARAMETER;
        }
    }

    // step 1. calculate sha256(shared_dhkey || "MK000000")
    do
    {
        sgx_sha_state_handle_t handler;

        ret = sgx_sha256_init(&handler);
        if (ret != SGX_SUCCESS)
            break;

        ret = sgx_sha256_update((uint8_t *)dhkey, sizeof(sgx_ec256_dh_shared_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_update((uint8_t *)addon, (uint32_t)sizeof(addon), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_get_hash(handler, &hash);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        (void)sgx_sha256_close(handler);

    } while(0);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;
    // step 2. calculate aes-gcm(00000000, hash)
    do
    {
        sgx_cmac_state_handle_t cmac_handler;
        sgx_cmac_128bit_key_t cmac_key;

        memset((uint8_t *)&cmac_key, 0, sizeof(sgx_cmac_128bit_key_t));

        ret = sgx_cmac128_init(&cmac_key, &cmac_handler);
        if (ret != SGX_SUCCESS) {
            break;
        }

        ret = sgx_cmac128_update((uint8_t*)&hash, sizeof(sgx_sha256_hash_t), cmac_handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(cmac_handler);
            break;
        }

        ret = sgx_cmac128_final(cmac_handler, &mac);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(cmac_handler);
            break;
        }

        (void)sgx_cmac128_close(cmac_handler);

    } while (0);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    memcpy(outputkey, &mac, sizeof(uint8_t) * 16);

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_responder_init_session(sgx_ea_session_id_t *sessionid)
{
    sgx_ea_context_t * ptr_ea_ctx = NULL;
    
    if (!sessionid)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    ptr_ea_ctx = (sgx_ea_context_t *)malloc(sizeof(sgx_ea_context_t));
    if (!ptr_ea_ctx) {
        return SGX_EA_ERROR_OUT_OF_MEMORY;
    }
    memset(ptr_ea_ctx, 0, sizeof(sgx_ea_context_t));

    ptr_ea_ctx->sessionid = gen_session_id();    
    ptr_ea_ctx->status = SGX_EA_SESSION_INITED;

    *sessionid = ptr_ea_ctx->sessionid;

    sgx_spin_lock(&m_ea_db_lock);
    m_ea_responder_ctx_vec.push_back(ptr_ea_ctx);
    sgx_spin_unlock(&m_ea_db_lock);

    return SGX_EA_SUCCESS;
}

/*
 * sgx_target_info_t * target: this is QE's target info.
 */
sgx_ea_status_t sgx_ea_responder_gen_msg1_content(sgx_ea_session_id_t sessionid, const sgx_ea_nonce_t *nonce, const sgx_target_info_t * target, sgx_tea_msg1_content_t * p_msg1content)
{
    sgx_status_t ret;
    sgx_ea_context_t * ptr_ea_ctx = NULL;
    sgx_ec256_public_t pubkey;
    sgx_ec256_private_t privkey;
    sgx_ecc_state_handle_t ecchandle;
    sgx_report_t app_report;
   
    if (!target || !p_msg1content || !nonce)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_spin_lock(&m_ea_db_lock);
    if ((ptr_ea_ctx = find_ea_session(sessionid)) == NULL) {
        sgx_spin_unlock(&m_ea_db_lock);
        return SGX_EA_ERROR_INVALID_PARAMETER;
    }        
    sgx_spin_unlock(&m_ea_db_lock);

    if (ptr_ea_ctx->status != SGX_EA_SESSION_INITED)
        return SGX_EA_ERROR_UNEXPECTED;

    ret = sgx_ecc256_open_context(&ecchandle);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    ret = sgx_ecc256_create_key_pair(&privkey, &pubkey, ecchandle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecchandle);
        return SGX_EA_ERROR_CRYPTO;
    }

    sgx_ecc256_close_context(ecchandle);

    // report data = SHA256(nonce || pubkey)
    sgx_sha256_hash_t hash;
    do
    {
        sgx_sha_state_handle_t handler;

        ret = sgx_sha256_init(&handler);
        if (ret != SGX_SUCCESS)
            break;
        
        ret = sgx_sha256_update((uint8_t *)nonce, sizeof(sgx_ea_nonce_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_update((uint8_t *)&pubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_get_hash(handler, &hash);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        sgx_sha256_close(handler);
    } while (0);    

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    sgx_report_data_t report_data = {0};

    memcpy((uint8_t *)report_data.d, (uint8_t *)&hash, sizeof(sgx_sha256_hash_t));

    ret = sgx_create_report(target, &report_data, &app_report);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_GEN_REPORT;
    }

    p_msg1content->nonce = *nonce;    
    p_msg1content->pubkey = pubkey;
    p_msg1content->report = app_report;

    sgx_target_info_t self_target;

    ret = sgx_self_target(&self_target);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_GEN_REPORT;
    }

    ptr_ea_ctx->ecpubkey = pubkey;
    ptr_ea_ctx->ecprivkey = privkey;

    ptr_ea_ctx->status = SGX_EA_SESSION_WAIT_FOR_MSG2;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_responder_gen_msg3_content(sgx_ea_session_id_t sessionid, const sgx_tea_msg2_content_t * p_msg2, sgx_tea_msg3_content_t * p_msg3)
{
    sgx_status_t ret;
    sgx_ea_status_t earet;
    
    sgx_ea_context_t *ptr_ea_session = NULL;
    sgx_aes_gcm_128bit_key_t mk, sk;
    sgx_tea_msg3_content_t msg3content;

    if (!p_msg2 || !p_msg3)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_spin_lock(&m_ea_db_lock);
    if ((ptr_ea_session = find_ea_session(sessionid)) == NULL) {
        sgx_spin_unlock(&m_ea_db_lock);
        return SGX_EA_ERROR_INVALID_PARAMETER;
    }        
    sgx_spin_unlock(&m_ea_db_lock);    

    if (ptr_ea_session->status != SGX_EA_SESSION_WAIT_FOR_MSG2)
        return SGX_EA_ERROR_UNEXPECTED;

    // check message 2 content:
    //    report data is SHA256(pubkey_initiator || pubkey_responder)
    //    ISVSVN, MRSIGNER, ATTRIBUTE
    do
    {
        sgx_sha_state_handle_t handler;
        sgx_sha256_hash_t hash;

        ret = sgx_sha256_init(&handler);
        if (ret != SGX_SUCCESS)
            break;

        ret = sgx_sha256_update((uint8_t*)&p_msg2->pubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }
      
        ret = sgx_sha256_update((uint8_t*)&ptr_ea_session->ecpubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        ret = sgx_sha256_get_hash(handler, &hash);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handler);
            break;
        }

        if (0 != memcmp((uint8_t *)&hash, (uint8_t *)p_msg2->report.body.report_data.d, sizeof(hash))) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

        sgx_sha256_close(handler);
    } while(0);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_INVALID_REPORT;

    do
    {
        sgx_ecc_state_handle_t ecc_handler;

        ret = sgx_ecc256_open_context(&ecc_handler);
        if (ret != SGX_SUCCESS)
            break;

        ret = sgx_ecc256_compute_shared_dhkey(&ptr_ea_session->ecprivkey, const_cast<sgx_ec256_public_t *>(&p_msg2->pubkey), &ptr_ea_session->ecsharedkey, ecc_handler);
        if (ret != SGX_SUCCESS) {
            sgx_ecc256_close_context(ecc_handler);
            break;
        }

        (void)sgx_ecc256_close_context(ecc_handler);
    } while(0);    

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    earet = derivekey(SESSION_MK, &ptr_ea_session->ecsharedkey, reinterpret_cast<sgx_cmac_128bit_tag_t *>(&mk));
    if (earet != SGX_EA_SUCCESS)
        return earet;

    earet = derivekey(SESSION_SK, &ptr_ea_session->ecsharedkey, reinterpret_cast<sgx_cmac_128bit_tag_t *>(&sk));
    if (earet != SGX_EA_SUCCESS)
        return earet;
    
    // compose message 3 content
    sgx_cmac_128bit_tag_t mac;
    do
    {
        // calculate AES_CMAC(mk, result || initiator_pubkey || responder_pubkey)
        sgx_cmac_state_handle_t handler;
        
        int result = 0;

        ret = sgx_cmac128_init((sgx_cmac_128bit_tag_t *)&mk, &handler);
        if (ret != SGX_SUCCESS)
            break;
    
        ret = sgx_cmac128_update((uint8_t*)&result, sizeof(int), handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }

        ret = sgx_cmac128_update((uint8_t *)&p_msg2->pubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }

        ret = sgx_cmac128_update((uint8_t *)&ptr_ea_session->ecpubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }
        
        ret = sgx_cmac128_final(handler, &mac);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }

        sgx_cmac128_close(handler);
    }while (0);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO; 

    msg3content.result = 0; // 0 means success
    memcpy((uint8_t*)&msg3content.mac, (uint8_t *)&mac, sizeof(mac));
    *p_msg3 = msg3content;
    
    ptr_ea_session->status = SGX_EA_SESSION_ESTABLISHED;
    memcpy((uint8_t *)&ptr_ea_session->mk, (uint8_t*)&mk, AES_128_CMAC_SIZE);
    memcpy((uint8_t *)&ptr_ea_session->sk, (uint8_t*)&sk, AES_128_CMAC_SIZE);

    return SGX_EA_SUCCESS;
}

#ifdef DEBUG
sgx_ea_status_t sgx_ea_responder_get_mk(sgx_ea_session_id_t sessionid, sgx_aes_gcm_128bit_key_t *key)
{
    sgx_ea_context_t *ptr_ea_session = NULL;

    if (!key)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_spin_lock(&m_ea_db_lock);
    if ((ptr_ea_session = find_ea_session(sessionid)) == NULL) {
        sgx_spin_unlock(&m_ea_db_lock);
        return SGX_EA_ERROR_INVALID_PARAMETER;
    }        
    sgx_spin_unlock(&m_ea_db_lock);    

    if (ptr_ea_session->status != SGX_EA_SESSION_ESTABLISHED)
        return SGX_EA_ERROR_UNEXPECTED;
   
    memcpy(key, &ptr_ea_session->mk, sizeof(uint8_t) * 16);

    return SGX_EA_SUCCESS;
}
#endif

sgx_ea_status_t sgx_ea_responder_get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size)
{
    if (!encrypted_msg || !p_decrypted_msg_size || (encrypted_msg_size < sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (sgx_is_within_enclave(encrypted_msg, encrypted_msg_size))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_tea_sec_msg_t * p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    *p_decrypted_msg_size = p_sec_msg->aes_gcm_data.payload_size;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_responder_decrypt_msg(sgx_ea_session_id_t sessionid, const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, 
                                                uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size)
{
    sgx_status_t ret;
    sgx_tea_sec_msg_t * p_sec_msg = NULL;
    sgx_ea_context_t *ptr_ea_session = NULL;

    if (!encrypted_msg || !p_decrypted_msg
        || (encrypted_msg_size < sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;
    
    p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    if (decrypted_msg_size < p_sec_msg->aes_gcm_data.payload_size)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (sgx_is_within_enclave(encrypted_msg, encrypted_msg_size)
        || sgx_is_within_enclave(p_decrypted_msg, decrypted_msg_size))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_spin_lock(&m_ea_db_lock);
    if ((ptr_ea_session = find_ea_session(sessionid)) == NULL) {
        sgx_spin_unlock(&m_ea_db_lock);
        return SGX_EA_ERROR_INVALID_PARAMETER;
    }
    sgx_spin_unlock(&m_ea_db_lock);

    if (ptr_ea_session->status != SGX_EA_SESSION_ESTABLISHED)
        return SGX_EA_ERROR_UNINITIALIZED;

    uint8_t authenticated_data[AES_128_GCM_AAD_SIZE] = {0x23, 0x31, 0x98, 0x76, 0x67, 0x34, 0x86, 0x92, 0x36, 0x85, 0x72, 0x87, 0x68, 0x72, 0x84, 0x89};

    ret = sgx_rijndael128GCM_decrypt(&ptr_ea_session->sk, p_sec_msg->aes_gcm_data.payload, 
                                     decrypted_msg_size, p_decrypted_msg,
                                     reinterpret_cast<uint8_t *>(p_sec_msg->aes_gcm_data.reserved), sizeof(p_sec_msg->aes_gcm_data.reserved), 
                                     authenticated_data, sizeof(authenticated_data),
                                     &p_sec_msg->aes_gcm_data.payload_tag);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    return SGX_EA_SUCCESS;        
}

sgx_ea_status_t sgx_ea_responder_get_encrypted_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize)
{
    if (!p_secmsgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    *p_secmsgsize = (uint32_t)sizeof(sgx_tea_sec_msg_t) + rawmsgsize;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_responder_encrypt_msg(sgx_ea_session_id_t sessionid, const uint8_t * p_rawmsgbuf, uint32_t rawmsgsize,
                                                uint8_t * p_secmsgbuf, uint32_t secmsgsize)
{
    sgx_status_t ret;
    sgx_ea_context_t *ptr_ea_session = NULL;
    uint8_t authenticated_data[AES_128_GCM_AAD_SIZE] = 
                {0x23, 0x31, 0x98, 0x76, 0x67, 0x34, 0x86, 0x92, 0x36, 0x85, 0x72, 0x87, 0x68, 0x72, 0x84, 0x89}; 

    if (!p_rawmsgbuf || !p_secmsgbuf)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if ((rawmsgsize + (uint32_t)sizeof(sgx_tea_sec_msg_t) < rawmsgsize) 
       || (secmsgsize < rawmsgsize + (uint32_t)sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (sgx_is_within_enclave(p_rawmsgbuf, rawmsgsize)
       || sgx_is_within_enclave(p_secmsgbuf, secmsgsize))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_spin_lock(&m_ea_db_lock);
    if ((ptr_ea_session = find_ea_session(sessionid)) == NULL) {
        sgx_spin_unlock(&m_ea_db_lock);
        return SGX_EA_ERROR_INVALID_PARAMETER;
    }
    sgx_spin_unlock(&m_ea_db_lock);

    if (ptr_ea_session->status != SGX_EA_SESSION_ESTABLISHED)
        return SGX_EA_ERROR_UNINITIALIZED;
    
    sgx_tea_sec_msg_t * p_tea_sec_msg = (sgx_tea_sec_msg_t *)p_secmsgbuf;

    p_tea_sec_msg->aes_gcm_data.payload_size = rawmsgsize;

    ret = sgx_rijndael128GCM_encrypt(&ptr_ea_session->sk, p_rawmsgbuf, rawmsgsize,
                                reinterpret_cast<uint8_t *>(p_tea_sec_msg->aes_gcm_data.payload), 
                                reinterpret_cast<uint8_t *>(p_tea_sec_msg->aes_gcm_data.reserved), sizeof(p_tea_sec_msg->aes_gcm_data.reserved),
                                authenticated_data, AES_128_GCM_AAD_SIZE,
                                &p_tea_sec_msg->aes_gcm_data.payload_tag);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_responder_close_ea_session(sgx_ea_session_id_t sessionid)
{
	sgx_spin_lock(&m_ea_db_lock);
	close_ea_session(sessionid);
    sgx_spin_unlock(&m_ea_db_lock);
	
	return SGX_EA_SUCCESS;
}
