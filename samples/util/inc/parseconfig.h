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
#ifndef _PARSECONF_H_
#define _PARSECONF_H_

#include <string>
#include "sgx_ea_error.h"

#pragma pack(push, 1)
struct sgx_ea_server_t {
    std::string m_server;
    std::string m_server_filesock;
    short m_port;
#ifdef __cplusplus
    sgx_ea_server_t();
    sgx_ea_server_t(std::string server, short port);
#endif
};
#pragma pack(pop)

sgx_ea_status_t parseconfig(sgx_ea_server_t&);
#endif
