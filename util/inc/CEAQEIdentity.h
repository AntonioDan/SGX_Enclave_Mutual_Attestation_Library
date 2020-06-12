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
#ifndef _CEAQEIDENTITY_H_
#define _CEAQEIDENTITY_H_

#include <string>
#include <vector>
#include "JsonParser.h"
#include "sgx_attributes.h"
#include "sgx_report.h"

class CEAQEIdentity {
    public:
        enum {
            MRSIGNER_HEX_LENGTH = 64,
            ATTRIBUTES_HEX_LENGTH = 32,
            MISCSELECT_HEX_LENGTH = 8,
        };
    public:
        struct QETcbEntry {
            uint32_t isvsvn;
            std::string status;
        };
    public:
        CEAQEIdentity();
        ~CEAQEIdentity();

    public:
        void parse(const std::string&);

    public:
        const sgx_measurement_t& get_mr_signer() const;
        const sgx_isv_svn_t& get_isvsvn() const;
        const sgx_attributes_t& get_attributes() const;

    private:
        std::string m_s_id;
        int m_version;
        std::string m_s_issuedate;
        std::string m_s_nextupdate;
        int m_tcbevaluationdatanum;
        uint32_t m_misc_select;
        uint32_t m_misc_select_mask;
        sgx_attributes_t m_attributes;
        sgx_measurement_t m_mr_signer;
        std::vector<QETcbEntry> m_vec_tcb;
        sgx_isv_svn_t m_isvsvn;

     private:
        JsonParser jsonparser;
};

#endif
