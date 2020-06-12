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
#include "CEAServer.h"

#include "CSelector.h"
#include "IServerSocket.h"
#include "ICommunicationSocket.h"
#include "SocketTranslator.h"
#include "CEAServerMsg.h"
#include "sgx_ea.h"

#include <string>
#include <list>
using namespace std;

CEAServer::CEAServer(std::shared_ptr<IServerSocket> server_socket, std::shared_ptr<CSelector> selector) 
    : m_selector(selector), m_serversocket(server_socket), m_translator(NULL), m_shutdown(0)
{
    m_translator = std::make_shared<SocketTranslator>();
}

CEAServer::~CEAServer()
{
    shutdown();
    m_thread.join();    
}

void CEAServer::init()
{
    if (!m_selector || !m_serversocket || !m_translator) {
        return;
    }

    m_serversocket->init();

    m_thread.start();

    return;
}

void CEAServer::doWork()
{
    while (m_shutdown != 1) {
        // selector listen
        if (m_selector->select()) {
            if (m_selector->canAcceptConnection()) {
                ICommunicationSocket * newSock = m_serversocket->accept();
                m_selector->addSocket(newSock);
            }

            std::list<ICommunicationSocket *> newlist = m_selector->getSocsWithNewContent();
            
            /* read contents */
            std::list<ICommunicationSocket *>::iterator iter;

            for (iter = newlist.begin(); iter != newlist.end();) {                
                uint8_t * message = m_translator->receiveRequest(*iter);
                if (!message) {
                    m_selector->removeSocket(*iter);
                    iter = newlist.erase(iter);
                    continue;
                }

                EAServerMsg * receivedmsg = new EAServerMsg(message, *iter);

                m_thread.enqueue(receivedmsg);

                iter++;
            }
        }
    }
}

void CEAServer::shutdown()
{
    m_shutdown = 1;
}
