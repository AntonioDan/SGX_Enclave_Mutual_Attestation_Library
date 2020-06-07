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
