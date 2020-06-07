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
