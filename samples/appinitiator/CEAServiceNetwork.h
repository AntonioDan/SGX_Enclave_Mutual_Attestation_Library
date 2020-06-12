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
#ifndef _CEASERVICENETWORK_H__
#define _CEASERVICENETWORK_H_

#include <string>

#include "CEAServiceTranslator.h"
#include "ICommunicationSocket.h"

class CEAServiceNetwork : public CEAServiceTranslator {
    public:
        CEAServiceNetwork(const char *);
        CEAServiceNetwork(std::string, short);
        ~CEAServiceNetwork();

    public:
        size_t sendMessage(uint8_t * message, size_t size);
        uint8_t * recvMessage();
        uint8_t * sendandrecv(uint8_t * message, size_t size);
        void init();

    private:
        //UnixCommunicationSocket * m_socket;
        ICommunicationSocket *m_socket;
        const char * m_socketbase;
        std::string m_server_ip;
        short m_port;

    private:
        CEAServiceNetwork(const CEAServiceNetwork&);
        CEAServiceNetwork& operator=(const CEAServiceNetwork&);
};
#endif
