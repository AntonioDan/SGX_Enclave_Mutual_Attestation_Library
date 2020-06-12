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
#ifndef _EAQUEUE_H_
#define _EAQUEUE_H_

#include <queue>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>

#include "IEAQueue.h"

#define QUEUE_EXIT 0x1L

template <typename T>
class EAQueue : public IEAQueue<T> {
    public:
        EAQueue();
        ~EAQueue();

        void push(T*);
        T* blockingPop();
        void close();

    private:
        std::queue<T*> m_queue;
        pthread_mutex_t m_queueMutex;
        pthread_cond_t m_queueCond;
        volatile uint8_t m_events;

    private:
        EAQueue(const EAQueue&);
        EAQueue& operator=(const EAQueue&);
};

template <typename T>
EAQueue<T>::EAQueue() 
    : m_queue()
{
    int rc;

    rc = pthread_mutex_init(&m_queueMutex, NULL);
    if (rc != 0)
    {
        exit(-1);
    }

    rc = pthread_cond_init(&m_queueCond, NULL);
    if (rc != 0)
    {
        exit(-1);
    }

    m_events = 0;
}

template <typename T>
EAQueue<T>::~EAQueue()
{
    int rc;

    rc = pthread_mutex_destroy(&m_queueMutex);
    if (rc != 0)
    {
        exit(-1);
    }

    rc = pthread_cond_destroy(&m_queueCond);
    if (rc != 0)
    {
        exit(-1);
    }
}

template <typename T>
void EAQueue<T>::push(T* obj) 
{
    int rc;

    rc = pthread_mutex_lock(&m_queueMutex);
    if (rc != 0)
    {
        exit(-1);
    }

    m_queue.push(obj);

    rc = pthread_cond_signal(&m_queueCond);
    if (rc != 0)
    {
        exit(-1);
    }

    rc = pthread_mutex_unlock(&m_queueMutex);
    if (rc != 0)
    {
        exit(-1);
    }

    return;
}

template <typename T>
T* EAQueue<T>::blockingPop()
{
    int rc;
    T* value = NULL;

    rc = pthread_mutex_lock(&m_queueMutex);
    if (rc != 0)
    {
        exit(-1);
    }

    while (1)
    {
        if (m_events & QUEUE_EXIT) {
            while (!m_queue.empty()) {
                T * obj = m_queue.front();
                m_queue.pop();
                delete obj;
            }

            value = NULL;
            break;
        }

        if (m_queue.empty()) {
            rc = pthread_cond_wait(&m_queueCond, &m_queueMutex);
            if (rc != 0)
            {
               exit(-1); 
            }
        } else {
            value = m_queue.front();
            m_queue.pop();
            break;
        }
    }

    rc = pthread_mutex_unlock(&m_queueMutex);
    if (rc != 0) {
        exit(-1);
    }

    return value;
}

template<typename T>
void EAQueue<T>::close()
{
    int rc;

    rc = pthread_mutex_lock(&m_queueMutex);
    if (rc != 0)
    {
        exit(-1);
    }

    m_events = QUEUE_EXIT;

    rc = pthread_cond_signal(&m_queueCond);
    if (rc != 0)
    {
        exit(-1);
    }

    rc = pthread_mutex_unlock(&m_queueMutex);
}

#endif
