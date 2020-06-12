/*************************************************************************
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
************************************************************************/
#include "string.h"
#include "sgx_tcrypto.h"
#include "sgx_ea.h"
#include "sgx_tea_key_exchange_initiator.h"
#include "sgx_ea_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_trts.h"
#include "sgx_ea_ctx.h"

struct sgx_ea_initiator_context m_ea_initiator_ctx;

sgx_ea_status_t derivekey(uint8_t keytype, const sgx_ec256_dh_shared_t *dhkey, sgx_cmac_128bit_tag_t * outputkey)
{
    sgx_status_t ret;
    sgx_sha256_hash_t hash;
    sgx_cmac_128bit_tag_t mac;
    uint8_t addon[8] = {0};

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

sgx_ea_status_t sgx_ea_initiator_init_session(sgx_ea_session_id_t sessionid)
{
    m_ea_initiator_ctx.sessionid = sessionid;
    m_ea_initiator_ctx.status = SGX_EA_SESSION_WAIT_FOR_MSG1;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_initiator_uninit_session()
{
    m_ea_initiator_ctx.sessionid = SGX_EA_SESSION_INVALID_ID;
    m_ea_initiator_ctx.status = SGX_EA_SESSION_UNUSED;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_initiator_gen_msg2_content(sgx_tea_msg1_content_t * p_msg1content, sgx_target_info_t * p_qe_target, sgx_tea_msg2_content_t* p_msg2content)
{
    sgx_ec256_public_t pubkey;
    sgx_ec256_private_t privkey;
    sgx_ec256_dh_shared_t sharedkey;
    sgx_ecc_state_handle_t ecchandle;
    sgx_status_t ret;
    sgx_ea_status_t earet;
    sgx_aes_gcm_128bit_key_t mk, sk;

    if (!p_msg1content || !p_msg2content || !p_qe_target)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    memset(p_msg2content, 0, sizeof(sgx_tea_msg2_content_t));

    ret = sgx_ecc256_open_context(&ecchandle);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    ret = sgx_ecc256_create_key_pair(&privkey, &pubkey, ecchandle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecchandle);
        return SGX_EA_ERROR_CRYPTO;
    }

    ret = sgx_ecc256_compute_shared_dhkey(&privkey, &p_msg1content->pubkey, &sharedkey, ecchandle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecchandle);
        return SGX_EA_ERROR_CRYPTO;
    }

    sgx_ecc256_close_context(ecchandle);

    earet = derivekey(SESSION_MK, &sharedkey, reinterpret_cast<sgx_cmac_128bit_tag_t*>(&mk));
    if (earet != SGX_EA_SUCCESS) {
        return earet;
    }
    
    earet = derivekey(SESSION_SK, &sharedkey, reinterpret_cast<sgx_cmac_128bit_tag_t*>(&sk));
    if (earet != SGX_EA_SUCCESS) {
        return earet;
    }

    // generate msg3 content
    sgx_sha256_hash_t hash;
    do
    {
        sgx_sha_state_handle_t handle;

        ret = sgx_sha256_init(&handle);
        if (ret != SGX_SUCCESS)
            break;

        ret = sgx_sha256_update((uint8_t *)&pubkey, sizeof(pubkey), handle);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handle);
            break;
        }

        ret = sgx_sha256_update((uint8_t *)&p_msg1content->pubkey, sizeof(pubkey), handle);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handle);
            break;
        }

        ret = sgx_sha256_get_hash(handle, &hash);
        if (ret != SGX_SUCCESS) {
            sgx_sha256_close(handle);
            break;
        }

        sgx_sha256_close(handle);
    } while(0);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    sgx_report_data_t report_data = {0};
    sgx_report_t app_report;

    memcpy((uint8_t *)report_data.d, (uint8_t *)&hash, sizeof(sgx_sha256_hash_t));

    ret = sgx_create_report(p_qe_target, &report_data, &app_report);
    if (ret != SGX_SUCCESS) {
        return SGX_EA_ERROR_GEN_REPORT;
    }

    p_msg2content->pubkey = pubkey;
    p_msg2content->report = app_report;

    // compose qe_target_info
    sgx_target_info_t target;
    ret = sgx_self_target(&target);
    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_GEN_REPORT;

    m_ea_initiator_ctx.ecpubkey = pubkey;
    m_ea_initiator_ctx.peer_ecpubkey = p_msg1content->pubkey;
    m_ea_initiator_ctx.ecprivkey = privkey;
    m_ea_initiator_ctx.ecsharedkey = sharedkey;
    memcpy(&m_ea_initiator_ctx.mk, &mk, sizeof(uint8_t) * 16);
    memcpy(&m_ea_initiator_ctx.sk, &sk, sizeof(uint8_t) * 16);

    m_ea_initiator_ctx.status = SGX_EA_SESSION_WAIT_FOR_MSG3;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_ea_initiator_proc_msg3_content(sgx_tea_msg3_content_t *p_msg3)
{
    sgx_status_t ret;

    if (!p_msg3)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    // verify mac
    sgx_cmac_128bit_tag_t mac;
    do
    {
        // calculate AES_CMAC(mk, result || initiator_pubkey || responder_pubkey)
        sgx_cmac_state_handle_t handler;
        
        int result = p_msg3->result;

        ret = sgx_cmac128_init((sgx_cmac_128bit_key_t *)&m_ea_initiator_ctx.mk, &handler);
        if (ret != SGX_SUCCESS)
            break;
    
        ret = sgx_cmac128_update((uint8_t*)&result, sizeof(int), handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }

        ret = sgx_cmac128_update((uint8_t*)&m_ea_initiator_ctx.ecpubkey, sizeof(sgx_ec256_public_t), handler);
        if (ret != SGX_SUCCESS) {
            sgx_cmac128_close(handler);
            break;
        }

        ret = sgx_cmac128_update((uint8_t*)&m_ea_initiator_ctx.peer_ecpubkey, sizeof(sgx_ec256_public_t), handler);
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

    if (memcmp((uint8_t *)&mac, (uint8_t *)&p_msg3->mac, sizeof(mac)) != 0)
        return SGX_EA_ERROR_INVALID_REPORT;
    
    if (p_msg3->result == 0) {
        m_ea_initiator_ctx.status = SGX_EA_SESSION_ESTABLISHED;
    }else{
        m_ea_initiator_ctx.status = SGX_EA_SESSION_UNEXPECTED;
    }

    return SGX_EA_SUCCESS;
}

#ifdef DEBUG
sgx_ea_status_t sgx_ea_initiator_get_mk(sgx_aes_gcm_128bit_key_t * key)
{
    if (!key)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (m_ea_initiator_ctx.status != SGX_EA_SESSION_ESTABLISHED)
        return SGX_EA_ERROR_UNEXPECTED;

    memcpy(key, &m_ea_initiator_ctx.mk, sizeof(uint8_t) * 16);
    
    return SGX_EA_SUCCESS;
}
#endif

sgx_ea_status_t sgx_tea_initiator_get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize)
{
    if (!p_secmsgsize)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    *p_secmsgsize = (uint32_t)sizeof(sgx_tea_sec_msg_t) + rawmsgsize;
    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_tea_initiator_encrypt_msg(const uint8_t * p_rawmsgbuf, uint32_t rawmsgsize,
                                                uint8_t * p_secmsgbuf, uint32_t secmsgsize)
{
    sgx_status_t ret;
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

    if (m_ea_initiator_ctx.status != SGX_EA_SESSION_ESTABLISHED)
        return SGX_EA_ERROR_UNINITIALIZED;
    
    sgx_tea_sec_msg_t * p_tea_sec_msg = (sgx_tea_sec_msg_t *)p_secmsgbuf;

    p_tea_sec_msg->aes_gcm_data.payload_size = rawmsgsize;

    ret = sgx_rijndael128GCM_encrypt(&m_ea_initiator_ctx.sk, p_rawmsgbuf, rawmsgsize,
                                reinterpret_cast<uint8_t *>(p_tea_sec_msg->aes_gcm_data.payload), 
                                reinterpret_cast<uint8_t *>(p_tea_sec_msg->aes_gcm_data.reserved), sizeof(p_tea_sec_msg->aes_gcm_data.reserved),
                                authenticated_data, AES_128_GCM_AAD_SIZE,
                                &p_tea_sec_msg->aes_gcm_data.payload_tag);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_tea_initiator_get_decrypted_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size)
{
    if (!encrypted_msg || !p_decrypted_msg_size || (encrypted_msg_size < sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (sgx_is_within_enclave(encrypted_msg, encrypted_msg_size))
        return SGX_EA_ERROR_INVALID_PARAMETER;

    sgx_tea_sec_msg_t * p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    *p_decrypted_msg_size = p_sec_msg->aes_gcm_data.payload_size;

    return SGX_EA_SUCCESS;
}

sgx_ea_status_t sgx_tea_initiator_decrypt_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, 
                                                uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size)
{
    sgx_status_t ret;
    sgx_tea_sec_msg_t * p_sec_msg = NULL;    

    if (!encrypted_msg || !p_decrypted_msg
        || (encrypted_msg_size < sizeof(sgx_tea_sec_msg_t)))
        return SGX_EA_ERROR_INVALID_PARAMETER;
    
    p_sec_msg = (sgx_tea_sec_msg_t *)encrypted_msg;

    if (decrypted_msg_size < p_sec_msg->aes_gcm_data.payload_size)
        return SGX_EA_ERROR_INVALID_PARAMETER;

    if (sgx_is_within_enclave(encrypted_msg, encrypted_msg_size)
        || sgx_is_within_enclave(p_decrypted_msg, decrypted_msg_size))
        return SGX_EA_ERROR_INVALID_PARAMETER;  

    uint8_t authenticated_data[AES_128_GCM_AAD_SIZE] = {0x23, 0x31, 0x98, 0x76, 0x67, 0x34, 0x86, 0x92, 0x36, 0x85, 0x72, 0x87, 0x68, 0x72, 0x84, 0x89};

    ret = sgx_rijndael128GCM_decrypt(&m_ea_initiator_ctx.sk, p_sec_msg->aes_gcm_data.payload, 
                                     decrypted_msg_size, p_decrypted_msg,
                                     reinterpret_cast<uint8_t *>(p_sec_msg->aes_gcm_data.reserved), sizeof(p_sec_msg->aes_gcm_data.reserved), 
                                     authenticated_data, sizeof(authenticated_data),
                                     &p_sec_msg->aes_gcm_data.payload_tag);

    if (ret != SGX_SUCCESS)
        return SGX_EA_ERROR_CRYPTO;

    return SGX_EA_SUCCESS;        
}

sgx_ea_status_t sgx_tea_initiator_close_session()
{
    m_ea_initiator_ctx.status = SGX_EA_SESSION_INITED;

    memset(&m_ea_initiator_ctx, 0, sizeof(sgx_ea_initiator_context_t));
    
    return SGX_EA_SUCCESS;
}
