#include "Thread.h"
#include <assert.h>
#include <new>

Thread::Thread():m_shutdown(0) {}
Thread::~Thread() {
}

void Thread::start()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

    int rc = pthread_create(&m_thread, &attr, Thread::doWork, (void*)this);
    assert(rc == 0);
    (void)rc;

    pthread_attr_destroy(&attr);
}

void Thread::stop()
{
    m_shutdown = 1;
}

bool Thread::isStopped()
{
    return (m_shutdown == 1);
}

void Thread::run()
{

}

void* Thread::doWork(void * param)
{
    try 
    {
        Thread * thread = (Thread *)param;

        thread->run();
    }
    catch (std::bad_alloc& allocationException)
    {
        throw;
    }

    return NULL;
}

void Thread::join()
{
    pthread_join(m_thread, NULL);
}
