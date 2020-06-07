#include "CEAServer.h"

#include "CSelector.h"
#include "IServerSocket.h"
#include "ICommunicationSocket.h"
#include "SocketTranslator.h"
//#include "EAException.h"
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
    //delete m_translator;
    //delete m_serversocket;
    //delete m_selector;
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
                //EARawMsg * message = m_translator->receiveRequest(*iter);
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
