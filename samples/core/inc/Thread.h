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
