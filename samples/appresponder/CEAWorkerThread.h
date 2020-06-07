#ifndef _CEAWORKERTHREAD_H_
#define _CEAWORKERTHREAD_H_

#include "EAQueue.h"
#include "Thread.h"

class EARawMsg;
class EAServerMsg;

class CEAWorkerThread : public Thread {
    public:
        CEAWorkerThread();
        ~CEAWorkerThread();

    public:
        void enqueue(EAServerMsg *);

    private:
        void run(); // this is thread entity, check if there is entity in queue, then handle it

    private:
        EAQueue<EAServerMsg> m_queue;
};

#endif
