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
