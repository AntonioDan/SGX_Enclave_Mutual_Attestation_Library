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
