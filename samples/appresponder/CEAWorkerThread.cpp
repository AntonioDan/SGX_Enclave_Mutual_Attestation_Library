#include <stdio.h>
#include "sgx_ea_error.h"
#include "CEAWorkerThread.h"
#include "CEAMsghandler.h"

CEAWorkerThread::CEAWorkerThread(){}
CEAWorkerThread::~CEAWorkerThread(){}

void CEAWorkerThread::enqueue(EAServerMsg * value)
{
    if (!value)
        return;

    m_queue.push(value);
}

void CEAWorkerThread::run()
{
    while (!isStopped())
    {
        int rc;

        EAServerMsg * message = m_queue.blockingPop();
        
        //sgx_ea_raw_message_t * response = NULL;
    
        CEAMsgHandler * handler = CEAMsgHandlerProvider::GetInstance();
        if (!handler) {
            printf("Error: message handler is NULL!\n");
            continue;
        }
        rc = handler->procmsg(message);

        if (rc != SGX_EA_SUCCESS)
        {
            printf("Warning: failed to proc message.\n");
        }

        delete message;
    }
}

