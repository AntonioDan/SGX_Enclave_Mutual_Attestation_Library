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
#ifndef _SGX_EA_ERROR_H_
#define _SGX_EA_ERROR_H_

#define MK_EA_ERROR(x) (0x00001000 | (x))

typedef enum {
    SGX_EA_SUCCESS = MK_EA_ERROR(0),
    SGX_EA_ERROR_INVALID_PARAMETER = MK_EA_ERROR(1),
    SGX_EA_ERROR_UNEXPECTED = MK_EA_ERROR(2),
    SGX_EA_ERROR_LOAD_ENCLAVE = MK_EA_ERROR(3),
    SGX_EA_ERROR_OUT_OF_MEMORY = MK_EA_ERROR(4),
    SGX_EA_ERROR_CREATE_SESSION = MK_EA_ERROR(5),
    SGX_EA_ERROR_GEN_MSG1 = MK_EA_ERROR(6),
    SGX_EA_ERROR_NETWORK = MK_EA_ERROR(7),
    SGX_EA_ERROR_CRYPTO = MK_EA_ERROR(8),
    SGX_EA_ERROR_GEN_MSG3 = MK_EA_ERROR(9),
    SGX_EA_ERROR_INIT_SESSION = MK_EA_ERROR(10),
    SGX_EA_ERROR_FILE_ACCESS = MK_EA_ERROR(11),
    SGX_EA_ERROR_GEN_REPORT = MK_EA_ERROR(12),
    SGX_EA_ERROR_UNINITIALIZED = MK_EA_ERROR(13),
    SGX_EA_ERROR_ALREADY_INITIALIZED = MK_EA_ERROR(14),
    SGX_EA_ERROR_GEN_MSG2 = MK_EA_ERROR(15),
    SGX_EA_ERROR_INVALID_REPORT = MK_EA_ERROR(16),
    SGX_EA_ERROR_PROC_MSG3 = MK_EA_ERROR(17),
    SGX_EA_ERROR_PARSE_CONFIG = MK_EA_ERROR(18),
    SGX_EA_ERROR_CREATE_TRANSLATOR = MK_EA_ERROR(19),
    SGX_EA_ERROR_GET_KEY = MK_EA_ERROR(20),
    SGX_EA_ERROR_GEN_QUOTE = MK_EA_ERROR(21),
    SGX_EA_ERROR_ENCLAVE = MK_EA_ERROR(22),
    SGX_EA_ERROR_SYSTEM = MK_EA_ERROR(23),
    SGX_EA_ERROR_MESSAGE_FORMAT = MK_EA_ERROR(24),
    SGX_EA_ERROR_PARSE_FILE = MK_EA_ERROR(25),
    SGX_EA_ERROR_GET_QUOTE_SUPPLEMENTAL_DATA_SIZE = MK_EA_ERROR(26),
    SGX_EA_ERROR_VERIFY_QUOTE = MK_EA_ERROR(27),
    SGX_EA_ERROR_QUOTE_VERIFICATION_COLLATERAL_EXPIRED = MK_EA_ERROR(28),
    SGX_EA_ERROR_QE_IDENTITY = MK_EA_ERROR(29),
    SGX_EA_ERROR_QVE_IDENTITY = MK_EA_ERROR(30),
	SGX_EA_ERROR_MAC_MISMATCH = MK_EA_ERROR(31),
	SGX_EA_ERROR_NONCE_MISMATCH = MK_EA_ERROR(32),   
    SGX_EA_ERROR_SESSION_ALREADY_ESTABLISHED = MK_EA_ERROR(33)	
} sgx_ea_status_t;

#endif
