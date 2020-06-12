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
#include "CEAException.h"
#include "CEAQEIdentity.h"

CEAQEIdentity::CEAQEIdentity() : m_s_id("QE"), m_version(0), m_isvsvn(0) {}
CEAQEIdentity::~CEAQEIdentity() {}

void CEAQEIdentity::parse(const string& filecontent)
{
    jsonparser.parse(filecontent);

    const ::rapidjson::Value* enclaveIdentityNode = jsonparser.getField(string("enclaveIdentity"));
    if (enclaveIdentityNode == NULL)
        throw FormatException("can't find 'enclaveIdentity' field");

    if (!enclaveIdentityNode->IsObject())
        throw FormatException("failure to parse 'enclaveIdentity' field");
   
    pair<string, bool> idfield = jsonparser.getStringFieldOf(*enclaveIdentityNode, "id");
    if (idfield.second == false) {
        throw FormatException("failure to parse 'id' field");
    } else {
        m_s_id = idfield.first;
    }

    pair<vector<uint8_t>, bool> mrsigner_field = jsonparser.getHexstringFieldOf(*enclaveIdentityNode, "mrsigner", MRSIGNER_HEX_LENGTH);
    if (mrsigner_field.second == false) {
        throw FormatException("can't find 'mrsigner' field");
    } else {
        memcpy((uint8_t*)&m_mr_signer, mrsigner_field.first.data(), MRSIGNER_HEX_LENGTH / 2);
    }

    pair<vector<uint8_t>, bool> attributes_field = jsonparser.getHexstringFieldOf(*enclaveIdentityNode, "attributes", ATTRIBUTES_HEX_LENGTH);
    if (attributes_field.second == false) {
        throw FormatException("can't find 'attribute' field");
    } else {
        memcpy((uint8_t *)&m_attributes, attributes_field.first.data(), ATTRIBUTES_HEX_LENGTH / 2);
    }

    pair<int, bool> versionfield = jsonparser.getIntFieldOf(*enclaveIdentityNode, "version");
    if (versionfield.second == false) {
        throw FormatException("can't find 'version' field");
    } else {
        m_version = versionfield.first;
    }

    pair<int, bool> tcbEvaluationDataNumberfield = jsonparser.getIntFieldOf(*enclaveIdentityNode, "tcbEvaluationDataNumber");
    if (tcbEvaluationDataNumberfield.second == false) {
        throw FormatException("can't find 'tcbEvaluationDataNumber' field");
    } else {
        m_tcbevaluationdatanum = tcbEvaluationDataNumberfield.first;
    }

    pair<vector<uint8_t>, bool> misc_select_field = jsonparser.getHexstringFieldOf(*enclaveIdentityNode, "miscselect", MISCSELECT_HEX_LENGTH);
    if (misc_select_field.second == false) {
        throw FormatException("can't find 'miscselect' field");
    } else {
        memcpy((uint8_t *)&m_misc_select, misc_select_field.first.data(), MISCSELECT_HEX_LENGTH / 2);
    }

    pair<vector<uint8_t>, bool> misc_select_mask_field = jsonparser.getHexstringFieldOf(*enclaveIdentityNode, "miscselectMask", MISCSELECT_HEX_LENGTH);
    if (misc_select_mask_field.second == false) {
        throw FormatException("can't find 'miscselectMask' field");
    } else {
        memcpy((uint8_t *)&m_misc_select_mask, misc_select_mask_field.first.data(), MISCSELECT_HEX_LENGTH / 2);
    }

    const ::rapidjson::Value *tcbLevels_field = jsonparser.getFieldOf(*enclaveIdentityNode, "tcbLevels");
    assert(tcbLevels_field != NULL);
    assert(tcbLevels_field->IsArray() == true);
    for (::rapidjson::SizeType i = 0; i < tcbLevels_field->Size(); i++)
    {
        uint32_t tcbisvsvn;
        string tcbstatus;

        const ::rapidjson::Value& curTcbLevel = (*tcbLevels_field)[i];
        
        if (curTcbLevel.HasMember("tcb")) {
            const ::rapidjson::Value& tcbfield_v = curTcbLevel["tcb"];

            if (tcbfield_v.HasMember("isvsvn"))
                tcbisvsvn = tcbfield_v["isvsvn"].GetUint();
        } else {
            continue;
        }

        if (curTcbLevel.HasMember("tcbStatus")) {
            tcbstatus = curTcbLevel["tcbStatus"].GetString();
        } else {
            continue;
        }

        QETcbEntry tcbentry;
        tcbentry.isvsvn = tcbisvsvn;
        tcbentry.status = tcbstatus;

        m_vec_tcb.push_back(tcbentry);

        if (tcbstatus.compare("UpToDate") == 0)
            m_isvsvn = (sgx_isv_svn_t)tcbisvsvn;                
    }

    return ;
}

const sgx_measurement_t& CEAQEIdentity::get_mr_signer() const
{
    return m_mr_signer;
}

const sgx_attributes_t& CEAQEIdentity::get_attributes() const
{
    return m_attributes;
}

const sgx_isv_svn_t& CEAQEIdentity::get_isvsvn() const
{
    return m_isvsvn;
}
