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
#include <fstream>
#include <string>
using namespace std;
#include "parseconfig.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#define EA_SERVER_CONFIG_FILE "easerver.json"

sgx_ea_server_t::sgx_ea_server_t(std::string server, short port) : m_server(server), m_port(port) {}

sgx_ea_server_t::sgx_ea_server_t() {}

/* This function may throw exception when the file doesn't exist.
 * Caller needs to use try...catch... to handle the exception
 * */
sgx_ea_status_t parseconfig(sgx_ea_server_t& config)
{
    std::string eastrserver;
    std::ifstream ifs;

    ifs.open(EA_SERVER_CONFIG_FILE);
    ifs >> eastrserver;
    ifs.close();

    rapidjson::Document doc;
    doc.Parse(eastrserver.c_str());

    rapidjson::Value& port = doc["server_port"];
    rapidjson::Value& ip = doc["server_ip"];
    rapidjson::Value& filesock = doc["server_filesock"];

    config.m_server = ip.GetString();
    config.m_port = (short)port.GetInt();
    config.m_server_filesock = filesock.GetString();

    return SGX_EA_SUCCESS;
}
