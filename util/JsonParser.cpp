#include "JsonParser.h"
#include "TimeUtils.h"
#include "Bytes.h"

#include <stdexcept>
#include <algorithm>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/error/en.h>

bool JsonParser::parse(const string& json)
{
    if(json.empty())
    {
        return false;
    }

    jsonDocument.Parse(json.c_str());

    if (jsonDocument.HasParseError()) {
        //cout << GetParseError_En(jsonDocument.GetParseError()) << endl;
        //return false;
            throw logic_error("failed to parse json file");
    }
    return jsonDocument.IsObject();
}

const rapidjson::Value* JsonParser::getRoot() const
{
    return &jsonDocument;
}

const rapidjson::Value* JsonParser::getField(const string& fieldName) const
{
    if(!jsonDocument.HasMember(fieldName.c_str()))
    {
        return nullptr;
    }
    return &jsonDocument[fieldName.c_str()];
}

pair<vector<uint8_t>, bool> JsonParser::getHexstringFieldOf(const ::rapidjson::Value& parent, const string& fieldName, size_t length) const
{
    pair<vector<uint8_t>, bool> FailedReturnValue = make_pair(vector<uint8_t>{}, false);
    if (!parent.HasMember(fieldName.c_str()))
    {
        return FailedReturnValue; 
    }

    const ::rapidjson::Value& property_v = parent[fieldName.c_str()];
    if (!property_v.IsString())
    {
        return FailedReturnValue;
    }
    
    const string propertyStr = property_v.GetString();
    if ((propertyStr.length() == length) && isValidHexstring(propertyStr))
    {
        return make_pair(hexStringToBytes(propertyStr.c_str()), true);
    }

    return FailedReturnValue;
}

pair<time_t, bool> JsonParser::getDateFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const
{
    pair<time_t, bool> FailedReturnValue = make_pair(time_t{}, false);

    if (!parent.HasMember(fieldname.c_str()))
    {
        return FailedReturnValue;
    }

    const auto& date = parent[fieldname.c_str()];
    if (!date.IsString() || !isValidTimeString(date.GetString()))
        return FailedReturnValue;

    return make_pair(getEpochTimeFromString(date.GetString()), true);
}

pair<string, bool> JsonParser::getStringFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const
{
    pair<string, bool> FailedReturnValue = make_pair(string{}, false);

    if (!parent.HasMember(fieldname.c_str()))
        return FailedReturnValue;

    const ::rapidjson::Value& property_v = parent[fieldname.c_str()];
    if (!property_v.IsString())
        return FailedReturnValue;

    return make_pair(property_v.GetString(), true);
}

pair<int, bool> JsonParser::getIntFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const
{
    pair<int, bool> FailedReturnValue = make_pair(int(-1), false);

    if (!parent.HasMember(fieldname.c_str()))
        return FailedReturnValue;

    const ::rapidjson::Value& property_v = parent[fieldname.c_str()];
    if (!property_v.IsInt())
        return FailedReturnValue;

    return make_pair(property_v.GetInt(), true);
}

const rapidjson::Value* JsonParser::getFieldOf(const ::rapidjson::Value& parent, const string& fieldName) const
{
    if (!parent.HasMember(fieldName.c_str()))
        return NULL;

    return &parent[fieldName.c_str()];
}

bool JsonParser::isValidHexstring(const string& hexstring) const
{
    return find_if(hexstring.cbegin(), hexstring.cend(),
                    [](const char c){return !::isxdigit(static_cast<unsigned char>(c));}) == hexstring.cend();
}
