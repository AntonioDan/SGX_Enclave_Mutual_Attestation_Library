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
#ifndef _EASERVER_H_
#define _EASERVER_H_

#include "CSelector.h"
#include "IServerSocket.h"
#include "ITranslator.h"
#include "CEAWorkerThread.h"
#include <memory>

class CEAServer {
    public:
        CEAServer(std::shared_ptr<IServerSocket> server_sock, std::shared_ptr<CSelector> selector);
        ~CEAServer();

    public:
        void init(); // call thread->start
        void doWork(); // call selector
        void shutdown();

    private:
		std::shared_ptr<CSelector> m_selector;
		std::shared_ptr<IServerSocket> m_serversocket;
		std::shared_ptr<ITranslator> m_translator;
        CEAWorkerThread  m_thread;
        volatile int m_shutdown;

    private:
        CEAServer(const CEAServer&);
        CEAServer& operator=(const CEAServer& obj); 
};

#endif
