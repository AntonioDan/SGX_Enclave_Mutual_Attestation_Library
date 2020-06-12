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
#ifndef _CEA_INITIATOR_H_
#define _CEA_INITIATOR_H_

#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "CSGXECDSAQuote.h"
#include "CEAServiceTranslator.h"
#include "sgx_urts.h"

class CEAInitiator {
    public:        
        CEAInitiator();
        ~CEAInitiator();
        
    public:
        sgx_ea_status_t init(sgx_target_info_t * p_qe_target);
        sgx_ea_status_t create_session(sgx_ea_session_id_t sid);
#ifdef DEBUG
        sgx_ea_status_t get_session_key(sgx_aes_gcm_128bit_key_t * key);        
#endif
        sgx_ea_status_t verify_qe_report(sgx_report_t * qereport, uint8_t * nonce, uint8_t * quote, uint32_t quote_size, sgx_isv_svn_t latest_qe_isvsvn = 4);
        sgx_ea_status_t get_qve_reportinfo(sgx_qe_report_info_t * qereportinfo);
        sgx_ea_status_t get_qe_reportinfo(sgx_qe_report_info_t * qereportinfo);
        sgx_ea_status_t verify_qve_result(time_t expiration_time, uint32_t collateral_expiration_status, uint32_t quote_verification_result, sgx_quote_nonce_t * p_nonce, const uint8_t * p_quote, uint32_t quote_size, sgx_report_t * qve_report, uint8_t * supplemental_data, uint32_t supplemental_data_size);
        sgx_ea_status_t get_sec_msg_size(uint32_t rawmsgsize, uint32_t *p_secmsgsize);
        sgx_ea_status_t encrypt_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                    uint8_t * p_encrypted_msg, uint32_t encrypted_msg_size);
        
        /**
         * This function wraps initiator enclave ECALL interface to encrypt the raw message input {p_rawmsg, rawmsgsize}.
         * 
         * @param p_rawmsg - this points to input message buffer
         * @param rawmsgsize - this is input message size
         * @param pp_secmsg - this points to output message buffer, the output message format is sgx_tea_sec_msg_t, see sgx_ea.h
         * @param p_secmsgsize - this points to output message buffer size.
         **/
        sgx_ea_status_t get_sec_msg(const uint8_t *p_rawmsg, uint32_t rawmsgsize,
                                            uint8_t **pp_secmsg, uint32_t *p_secmsgsize);

        /**
         * This function wraps initiator enclave ECALL interface to get plain message size.
         * 
         * @param encrypted_msg - this points to the input message buffer. The input message format is sgx_tea_sec_msg_t format, see sgx_ea.h
         * @param encrypted_msg_size - this is input message size.
         * @param p_decrypted_msg_size - this points to the output message buffer size.         * 
         **/
        sgx_ea_status_t get_plain_msg_size(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size, uint32_t * p_decrypted_msg_size);

        /**
         * This function wraps initiator enclave ECALL interface to get plain message.
         * 
         * @param encrypted_msg - this points to the input message buffer. The input message format is sgx_tea_sec_msg_t format, see sgx_ea.h
         * @param encrypted_msg_size - this is the input message size.
         * @param p_decrypted_msg - this points to decrypted message buffer, it's raw data format. This buffer is allocated by caller.
         * @param decrypted_msg_size - this is decrypted message size.         *  
         **/
        sgx_ea_status_t get_plain_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                       uint8_t * p_decrypted_msg, uint32_t decrypted_msg_size);

        /**
         * This function wraps both ECALL interface to get plain message size and decrypt message.
         * 
         * @param encrypted_msg - this points to the input message buffer. The input message format is sgx_tea_sec_msg_t format, see sgx_ea.h
         * @param encrypted_msg_size - this is the input message size.
         * @param pp_decrypted_msg - this points to decrypted message buffer, it's raw data format. This function would allocate buffer according to plaintext message size, and return the plain message size to p_decrypted_msg_size buffer.
         * @param p_decrypted_msg_size - this is decrypted message size.         *  
         *
         **/
        sgx_ea_status_t get_plain_msg(const uint8_t * encrypted_msg, uint32_t encrypted_msg_size,
                                       uint8_t ** pp_decrypted_msg, uint32_t * p_decrypted_msg_size);

        sgx_ea_status_t close_ea_session();

        sgx_ea_status_t uninit();

    private:
        bool m_inited;
        sgx_enclave_id_t m_eid;
        sgx_ea_role_t m_role;
        sgx_target_info_t m_qe_target;
        
    private:
        CEAInitiator(const CEAInitiator&);
        CEAInitiator& operator=(const CEAInitiator&);   
};

#endif
