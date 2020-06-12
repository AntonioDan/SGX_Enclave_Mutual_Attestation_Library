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

#ifndef _SGX_AE_CONSTANTS_H_
#define _SGX_AE_CONSTANTS_H_

#define QVE_PROD_ID 2
#define QVE_ISVSVN  3

const sgx_measurement_t m_qe_mrsigner = {
    {0x8C, 0x4F, 0x57, 0x75, 0xD7, 0x96, 0x50, 0x3E,
     0x96, 0x13, 0x7F, 0x77, 0xC6, 0x8A, 0x82, 0x9A,
     0x00, 0x56, 0xAC, 0x8D, 0xED, 0x70, 0x14, 0x0B,
     0x08, 0x1B, 0x09, 0x44, 0x90, 0xC5, 0x7B, 0xFF}
};

const sgx_measurement_t m_qve_mrsigner = {
    {
        0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a,
        0x00, 0x56, 0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff,
    }
};

#endif
