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
#ifndef _THREAD_H_
#define _THREAD_H_

#include <pthread.h>

class Thread {
    public:
        Thread();
        virtual ~Thread();
    public:
        void start();
        void stop();
        void join();
        bool isStopped();

    private:
        virtual void run() = 0;

    private:
        pthread_t m_thread;
        volatile int m_shutdown;

    private:
        Thread(const Thread&);
        Thread& operator=(const Thread&);

        static void * doWork(void *param);
};

#endif
