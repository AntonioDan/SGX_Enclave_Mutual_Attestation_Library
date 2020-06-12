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

