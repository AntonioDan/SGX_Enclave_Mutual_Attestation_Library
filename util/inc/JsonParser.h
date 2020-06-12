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
#ifndef _JSONPARSER_H_
#define _JSONPARSER_H_

#include <memory>
#include <vector>
#include <string>
#include <rapidjson/document.h>
#include <time.h>
using namespace std;

class JsonParser
{
    public:
        bool parse(const string& json );
        const rapidjson::Value*  getRoot() const;
        const rapidjson::Value*  getField(const string& fieldname) const;
        const rapidjson::Value*  getFieldOf(const ::rapidjson::Value& parent, const string& fieldName) const;
        std::pair<vector<uint8_t>, bool> getHexstringFieldOf(const ::rapidjson::Value& parent, const string& fieldName, size_t length) const;
        std::pair<time_t, bool> getDateFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const;
        std::pair<string, bool> getStringFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const;
        std::pair<int, bool> getIntFieldOf(const ::rapidjson::Value& parent, const string& fieldname) const;
        bool isValidHexstring(const string& hexstring) const;

    private:
        rapidjson::Document jsonDocument;
};
#endif
