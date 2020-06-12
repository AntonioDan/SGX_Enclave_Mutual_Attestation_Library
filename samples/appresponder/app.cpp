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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <memory>

#include "CSelector.h"
#include "UnixServerTcpSocket.h"
#include "parseconfig.h"
#include "CEAServer.h"
#include "sgx_ea_error.h"
#include "se_trace.h"

std::shared_ptr<CEAServer> m_ea_server;
sgx_ea_server_t m_server_config;

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
        case SIGTERM:
        {
            if (m_ea_server) {
                m_ea_server->shutdown();                
            }
        }
        break;
    default:
        break;
    }

    exit(1);
}

int main(int argc, char * argv[])
{
    sgx_ea_status_t earet;

    (void)argc;
    (void)argv;
  
    // registger signal handler so to respond to user interception
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    earet = parseconfig(m_server_config);
    if (earet != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("failed to parse config file.\n");
        exit(-1);
    }

    try 
    {        
		std::shared_ptr<UnixServerTCPSocket> server_socket = std::make_shared<UnixServerTCPSocket>(m_server_config.m_port);        
		std::shared_ptr<CSelector> selector = std::make_shared<CSelector>(server_socket);        
		m_ea_server = std::make_shared<CEAServer>(server_socket, selector);

        m_ea_server->init();
        
        printf("Server is started, press Ctrl+C to exit...\n");
        
        m_ea_server->doWork();

    } catch (char const * error_msg)
    {
        printf("%s\n", error_msg);
    }

    return 0;
}
